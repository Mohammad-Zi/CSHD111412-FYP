import base64

import json

import re

import subprocess

import time

from datetime import datetime

from database import get_active_rules, get_audit_commands, get_ansible_hosts

# ---------------------------------------------------------

# Configuration

# ---------------------------------------------------------

ANSIBLE_DIRECTORY = "~/cis-project/ansible"

DEFAULT_TIMEOUT = 30

ANSIBLE_CONNECT_TIMEOUT = 10

# ---------------------------------------------------------

# General helpers

# ---------------------------------------------------------

def _text(value):

    """Convert a value to safe, readable text."""

    if value is None:

        return ""

    return str(value)

def _get_field(record, *names, default=None):

    """Read a field from either a dictionary or a database row."""

    if isinstance(record, dict):

        for name in names:

            if name in record:

                return record[name]

    else:

        for name in names:

            if hasattr(record, name):

                return getattr(record, name)

    return default

def _normalise_name(value):

    return _text(value).strip().lower()

def _get_host(host_name):

    """Resolve a selected GUI VM name against the Ansible inventory."""

    hosts = get_ansible_hosts() or []

    wanted = _normalise_name(host_name)

    for host in hosts:

        name = _get_field(host, "name", "inventory_name", "host")

        address = _get_field(

            host, "ansible_host", "address", "ip", "host"

        )

        if wanted in {

            _normalise_name(name),

            _normalise_name(address),

        }:

            target = _text(name or address).strip()

            if not target:

                break

            return target, host

    # Allow a target that is already an inventory alias or address.

    # Ansible will report an unknown target as an execution error.

    if host_name and wanted:

        return _text(host_name).strip(), None

    raise ValueError("No VM was selected.")

def _decode_output(value):

    """Handle subprocess output that may be text or bytes."""

    if value is None:

        return ""

    if isinstance(value, bytes):

        return value.decode("utf-8", errors="replace")

    return str(value)

# ---------------------------------------------------------

# Ansible execution

# ---------------------------------------------------------

def _run_remote_command(target, audit_command, timeout, requires_root=False):
    """Run a remote audit command through the WSL Ansible controller."""
    import shlex

    timeout = max(1, int(timeout or DEFAULT_TIMEOUT))
    payload = {
        "target": str(target),
        "command": str(audit_command),
        "timeout": timeout,
        "requires_root": bool(requires_root),
    }
    payload_b64 = base64.b64encode(
        json.dumps(payload).encode("utf-8")
    ).decode("ascii")

    remote_script = r"""
import base64
import json
import re
import subprocess
import sys

def emit(obj):
    print(json.dumps(obj), flush=True)

try:
    data = json.loads(base64.b64decode(sys.argv[1]).decode("utf-8"))
    timeout = max(1, int(data.get("timeout", 30)))
    wrapped = (
        str(data["command"])
        + '\n__cis_audit_rc=$?\n'
        + 'printf "\\n__CIS_AUDIT_RC__=%s\\n" "$__cis_audit_rc"\n'
        + 'exit 0'
    )
    # Use Ansible's normal multiline output. The compact -o format
    # escapes newlines and is harder to parse reliably across versions.
    cmd = [
        "ansible", str(data["target"]), "-i", "inventory",
        "-m", "shell", "-a", wrapped, "-T", str(min(timeout, 60))
    ]
    if data.get("requires_root"):
        cmd.append("--become")

    proc = subprocess.run(
        cmd, capture_output=True, text=True,
        timeout=timeout + 20, check=False
    )
    stdout_all = proc.stdout or ""
    stderr_all = proc.stderr or ""
    response = None

    # Ansible reports transport/task failures as JSON after =>.
    for line in stdout_all.splitlines():
        if " | UNREACHABLE! => " in line or " | FAILED! => " in line:
            prefix, result_text = line.split(" => ", 1)
            try:
                result = json.loads(result_text.strip())
            except (json.JSONDecodeError, ValueError):
                result = {}
            if "UNREACHABLE" in prefix.upper():
                message = result.get("msg", "Ansible could not reach the target host.")
            else:
                message = result.get("msg", "Ansible task failed.")
            response = {
                "ok": False, "returncode": proc.returncode,
                "stdout": stdout_all, "stderr": stderr_all,
                "error": str(message)
            }
            break

    if response is None:
        # Typical output: host | CHANGED | rc=0 >> followed by the
        # command's multiline stdout. Interpreter warnings are normally
        # on stderr and do not interfere with this header.
        header = re.search(
            r"(?m)^(.+?) \| (SUCCESS|CHANGED|FAILED|UNREACHABLE)!? \| rc=(-?\d+) >>[ \t]*$",
            stdout_all
        )
        if header:
            out = stdout_all[header.end():].strip("\r\n")
            marker = re.search(r"(?m)^__CIS_AUDIT_RC__=(-?\d+)\s*$", out)
            if marker:
                rc = int(marker.group(1))
                out = out[:marker.start()].rstrip("\r\n")
                response = {
                    "ok": True, "returncode": proc.returncode,
                    "stdout": "rc=" + str(rc) + " >> " + out,
                    "stderr": stderr_all.strip(), "error": None
                }
            else:
                response = {
                    "ok": False, "returncode": proc.returncode,
                    "stdout": stdout_all, "stderr": stderr_all,
                    "error": "Audit exit-code marker missing. Raw Ansible output: "
                             + stdout_all.strip()
                }

    if response is None:
        response = {
            "ok": False, "returncode": proc.returncode,
            "stdout": stdout_all, "stderr": stderr_all,
            "error": "Could not parse Ansible output. "
                     + (stderr_all.strip() or stdout_all.strip()
                        or "Ansible returned no output.")
        }
except subprocess.TimeoutExpired:
    response = {
        "ok": False, "returncode": None, "stdout": "", "stderr": "",
        "error": "Ansible command timed out."
    }
except Exception as exc:
    response = {
        "ok": False, "returncode": None, "stdout": "", "stderr": "",
        "error": type(exc).__name__ + ": " + str(exc)
    }

emit(response)
"""

    script_b64 = base64.b64encode(
        remote_script.encode("utf-8")
    ).decode("ascii")

    # The wrapper decodes the script, then resets argv so the embedded
    # script reads the payload from sys.argv[1].
    # With `python3 -c CODE ARG0 ARG1 ARG2`, sys.argv is
    # ['-c', ARG0, ARG1, ARG2]. Therefore the script and payload
    # are at indexes 2 and 3 respectively (not 1 and 2).
    wrapper = (
        "import base64,sys; "
        "script=base64.b64decode(sys.argv[2]); "
        "payload=sys.argv[3]; "
        "sys.argv=['<cis-audit>',payload]; "
        "exec(compile(script,'<cis-audit>','exec'))"
    )
    bash_command = (
        'cd "$HOME/cis-project/ansible" || exit 72; '
        "python3 -c " + shlex.quote(wrapper)
        + " cis-audit " + shlex.quote(script_b64)
        + " " + shlex.quote(payload_b64)
    )

    try:
        outer = subprocess.run(
            ["wsl.exe", "--", "bash", "-lc", bash_command],
            capture_output=True, text=True,
            timeout=timeout + 45, check=False
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False, "returncode": None, "stdout": "", "stderr": "",
            "error": "WSL/Ansible execution timed out."
        }
    except OSError as exc:
        return {
            "ok": False, "returncode": None, "stdout": "", "stderr": "",
            "error": f"Could not start WSL: {exc}"
        }

    stdout = outer.stdout or ""
    stderr = outer.stderr or ""
    for line in reversed(stdout.splitlines()):
        try:
            response = json.loads(line.strip())
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(response, dict) and "ok" in response:
            if outer.returncode != 0 and not response.get("error"):
                response["ok"] = False
                response["error"] = (
                    f"WSL exited with code {outer.returncode}: "
                    f"{stderr.strip() or stdout.strip()}"
                )
            return response

    if outer.returncode == 72:
        error = 'Cannot enter WSL directory "$HOME/cis-project/ansible".'
    else:
        error = (
            f"No valid JSON response from WSL (exit code {outer.returncode}). "
            f"STDOUT: {stdout!r}. STDERR: {stderr!r}"
        )
    return {
        "ok": False, "returncode": outer.returncode,
        "stdout": stdout, "stderr": stderr, "error": error
    }


# Compliance evaluation

# ---------------------------------------------------------

def _evaluate_result(command_record, remote_result):

    """

    Return (status, expected, actual).

    ERROR is reserved for transport/Ansible execution failures.

    A remote command's non-zero exit code is not automatically an

    error: grep returning 1 can correctly mean no match was found.

    """

    expected_value = _get_field(

        command_record,

        "expected_result",

        "expected",

        default=None,

    )

    match_type = _text(

        _get_field(

            command_record,

            "match_type",

            default="",

        )

    ).strip().upper()

    actual_stdout = _text(remote_result.get("stdout"))

    actual_stderr = _text(remote_result.get("stderr"))

    remote_error = remote_result.get("error")

    if remote_error:

        actual = (

            f"{remote_error}\n"

            f"STDOUT:\n{actual_stdout}\n"

            f"STDERR:\n{actual_stderr}"

        ).strip()

        return "ERROR", expected_value, actual

    if not remote_result.get("ok"):

        # Ansible itself failed, e.g. unreachable host or invalid

        # inventory/connection. Do not confuse this with a CIS fail.

        combined = (actual_stdout + "\n" + actual_stderr).strip()

        if (

            "UNREACHABLE" in combined.upper()

            or "UNREACHABLE!" in combined.upper()

            or "could not resolve hostname" in combined.lower()

            or "permission denied" in combined.lower()

            or "no hosts matched" in combined.lower()

        ):

            return "ERROR", expected_value, combined or (

                "Ansible could not connect to the target."

            )

        # A failed Ansible process without a parseable result is

        # different from a successfully executed remote command.

        return "ERROR", expected_value, combined or (

            f"Ansible exited with code "

            f"{remote_result.get('returncode')}."

        )

    # Extract the remote command's exit code from Ansible's one-line

    # output, e.g. "host | SUCCESS | rc=1 >>".

    combined = actual_stdout.strip()

    rc_match = re.search(r"\brc=(-?\d+)\b", combined)

    remote_rc = int(rc_match.group(1)) if rc_match else None

    # Remove the Ansible header so matching is performed on the

    # command output rather than the host/status text.

    output = combined

    if " >> " in output:

        output = output.split(" >> ", 1)[1]

    # Ansible may put the command output in stderr on failure.

    if not output and actual_stderr.strip():

        output = actual_stderr.strip()

    expected = _text(expected_value)

    actual = output.strip()

    # Explicit matching rules take precedence.

    if match_type == "EXIT_CODE":

        try:

            expected_code = int(expected)

        except (TypeError, ValueError):

            return "REVIEW", expected_value, (

                f"Invalid EXIT_CODE expected value: {expected!r}; "

                f"remote exit code: {remote_rc!r}"

            )

        if remote_rc is None:

            return "REVIEW", expected_value, (

                "Could not determine remote command exit code. "

                f"Output: {actual}"

            )

        return (

            "PASS" if remote_rc == expected_code else "FAIL",

            expected_value,

            f"Exit code: {remote_rc}; output: {actual}",

        )

    if match_type == "NO_OUTPUT":

        return (

            "PASS" if not actual else "FAIL",

            expected_value,

            actual if actual else "(no output)",

        )

    if match_type == "EXACT":

        return (

            "PASS" if actual == expected else "FAIL",

            expected_value,

            actual,

        )

    if match_type == "CONTAINS":

        return (

            "PASS" if expected in actual else "FAIL",

            expected_value,

            actual,

        )

    if match_type == "NOT_CONTAINS":

        return (

            "PASS" if expected not in actual else "FAIL",

            expected_value,

            actual,

        )

    if match_type == "REGEX":

        try:

            matched = re.search(expected, actual) is not None

        except re.error as exc:

            return "REVIEW", expected_value, (

                f"Invalid expected-result regex: {exc}. "

                f"Actual output: {actual}"

            )

        return (

            "PASS" if matched else "FAIL",

            expected_value,

            actual,

        )

    # No match type was specified. A NULL expected_result commonly

    # means that no output is expected for a grep-based audit.

    if not match_type and expected_value is None:

        if remote_rc == 0 and not actual:

            return "PASS", expected_value, "(no output)"

        if remote_rc == 1 and not actual:

            return "PASS", expected_value, "(no match; no output)"

        if actual:

            return "FAIL", expected_value, actual

        return "REVIEW", expected_value, (

            "No expected-result matching rule was configured, "

            f"and the remote exit code was {remote_rc!r}."

        )

    # Without an explicit match type and expected value, it is unsafe

    # to claim compliance.

    if not match_type:

        return "REVIEW", expected_value, (

            "Missing match_type; compliance cannot be evaluated. "

            f"Actual output: {actual}"

        )

    return "REVIEW", expected_value, (

        f"Unsupported match_type: {match_type}. "

        f"Actual output: {actual}"

    )

# ---------------------------------------------------------

# Audit runner — called by the GUI as run_audit(vm_name)

# ---------------------------------------------------------

def run_audit(vm_name):

    """

    Run all active AUDIT commands against one selected VM.

    Returns a list of dictionaries suitable for the GUI results

    table. Individual command failures are returned as ERROR records

    instead of terminating the entire audit.

    """

    results = []

    audit_started = time.time()

    try:

        target, host_record = _get_host(vm_name)

    except Exception as exc:

        return [{

            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

            "vm": _text(vm_name),

            "cis_id": "",

            "title": "Load VM inventory",

            "command": "",

            "status": "ERROR",

            "expected": "",

            "actual": f"{type(exc).__name__}: {exc}",

            "details": str(exc),

        }]

    try:

        rules = get_active_rules() or []

    except Exception as exc:

        return [{

            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

            "vm": target,

            "cis_id": "",

            "title": "Load active CIS rules",

            "command": "",

            "status": "ERROR",

            "expected": "",

            "actual": f"{type(exc).__name__}: {exc}",

            "details": str(exc),

        }]

    for rule in rules:

        rule_id = _get_field(rule, "rule_id", "id")

        cis_id = _get_field(rule, "cis_id", "rule_cis_id", default="")

        title = _get_field(

            rule,

            "title",

            "rule_title",

            "name",

            default=f"CIS rule {cis_id or rule_id}",

        )

        try:

            try:

                commands = get_audit_commands(rule_id)

            except TypeError:

                # Compatibility with a database helper that accepts

                # no rule_id argument.

                commands = get_audit_commands()

            commands = commands or []

            # Keep only audit commands for this rule.

            filtered = []

            for item in commands:

                item_rule_id = _get_field(item, "rule_id")

                command_type = _text(

                    _get_field(item, "command_type", default="AUDIT")

                ).strip().upper()

                if item_rule_id is not None and str(item_rule_id) != str(rule_id):

                    continue

                if command_type and command_type != "AUDIT":

                    continue

                filtered.append(item)

            filtered.sort(

                key=lambda item: int(

                    _get_field(item, "step_order", default=0) or 0

                )

            )

        except Exception as exc:

            results.append({

                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

                "vm": target,

                "cis_id": _text(cis_id),

                "title": _text(title),

                "command": "",

                "status": "ERROR",

                "expected": "",

                "actual": (

                    f"Could not load audit commands: "

                    f"{type(exc).__name__}: {exc}"

                ),

                "details": str(exc),

            })

            continue

        if not filtered:

            results.append({

                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

                "vm": target,

                "cis_id": _text(cis_id),

                "title": _text(title),

                "command": "",

                "status": "REVIEW",

                "expected": "",

                "actual": "No active AUDIT command was found for this rule.",

                "details": "Check the cis_commands table and command_type.",

            })

            continue

        for command_record in filtered:

            audit_command = _text(

                _get_field(command_record, "command", "audit_command")

            ).strip()

            timeout_value = _get_field(

                command_record,

                "timeout_seconds",

                "timeout",

                default=DEFAULT_TIMEOUT,

            )

            try:

                timeout = max(1, int(timeout_value or DEFAULT_TIMEOUT))

            except (TypeError, ValueError):

                timeout = DEFAULT_TIMEOUT

            command_cis_id = _get_field(

                command_record, "cis_id", default=cis_id

            )

            command_title = _get_field(

                command_record, "title", "rule_title", default=title

            )

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if not audit_command:

                status = "ERROR"

                expected = _get_field(

                    command_record, "expected_result", "expected"

                )

                actual = "Audit command is empty."

            else:

                remote_result = _run_remote_command(

                    target,

                    audit_command,

                    timeout,

                )

                status, expected, actual = _evaluate_result(

                    command_record,

                    remote_result,

                )

            results.append({

                "timestamp": timestamp,

                "vm": target,

                "cis_id": _text(command_cis_id),

                "title": _text(command_title),

                "command": audit_command,

                "status": status,

                "expected": _text(expected) if expected is not None else "None",

                "actual": _text(actual),

                "details": _text(actual),

            })

    if not results:

        results.append({

            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

            "vm": target,

            "cis_id": "",

            "title": "Audit",

            "command": "",

            "status": "REVIEW",

            "expected": "",

            "actual": "No active CIS audit commands were found.",

            "details": "Check active rules and AUDIT command records.",

        })

    elapsed = round(time.time() - audit_started, 2)

    print(

        f"[Audit] Finished VM {target}: "

        f"{len(results)} result(s) in {elapsed}s",

        flush=True,

    )

    return results
