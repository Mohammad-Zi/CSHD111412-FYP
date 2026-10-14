
import json
import os
import subprocess
from pathlib import Path

import mysql.connector
from dotenv import load_dotenv

PROJECT_DIR = Path(__file__).resolve().parent
load_dotenv(PROJECT_DIR / ".env")


def get_connection():
    """Connect to the project's MySQL database."""
    password = os.getenv("CIS_DB_PASSWORD")

    if not password:
        raise RuntimeError(
            f"CIS_DB_PASSWORD is missing from {PROJECT_DIR / '.env'}"
        )

    return mysql.connector.connect(
        host=os.getenv("CIS_DB_HOST", "localhost"),
        user=os.getenv("CIS_DB_USER", "cis_app"),
        password=password,
        database=os.getenv("CIS_DB_NAME", "CIS_DB"),
        connection_timeout=5,
    )


def get_ansible_inventory():
    """Read the existing Ansible inventory from WSL."""
    command = [
        "wsl.exe",
        "--",
        "bash",
        "-lc",
        'cd "$HOME/cis-project/ansible" && '
        "ansible-inventory -i inventory --list",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip()
            or result.stdout.strip()
            or f"Ansible inventory failed: exit code {result.returncode}"
        )

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Ansible returned invalid inventory JSON: {exc}"
        ) from exc


def get_ansible_hosts():
    """Return VM information for the GUI."""
    inventory = get_ansible_inventory()
    hostvars = inventory.get("_meta", {}).get("hostvars", {})

    hosts = []

    for hostname, variables in hostvars.items():
        if hostname.lower() == "localhost":
            continue

        hosts.append({
            "name": hostname,
            "ansible_host": variables.get("ansible_host", hostname),
            "ansible_user": variables.get("ansible_user", ""),
        })

    return hosts


def get_active_rules():
    """Return active CIS rules."""
    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT *
            FROM cis_rules
            WHERE is_active = 1
            ORDER BY rule_id
        """)

        return cursor.fetchall()

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


def get_audit_commands(rule_id=None):
    """Return active AUDIT commands, optionally for one rule."""
    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor(dictionary=True)

        query = """
            SELECT
                r.rule_id,
                r.cis_id,
                r.title AS rule_title,
                c.command_id,
                c.command_type,
                c.step_order,
                c.command,
                c.expected_result,
                c.match_type,
                c.timeout_seconds,
                c.requires_root,
                c.shell,
                c.description
            FROM cis_rules AS r
            JOIN cis_commands AS c
                ON c.rule_id = r.rule_id
            WHERE r.is_active = 1
              AND UPPER(c.command_type) = 'AUDIT'
        """

        params = ()

        if rule_id is not None:
            query += " AND r.rule_id = %s"
            params = (rule_id,)

        query += """
            ORDER BY r.rule_id, c.step_order, c.command_id
        """

        cursor.execute(query, params)
        return cursor.fetchall()

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


def test_database():
    """Return a useful database connection diagnostic."""
    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute("SELECT DATABASE(), VERSION()")

        database_name, version = cursor.fetchone()

        return (
            True,
            f"Connected to {database_name}; MySQL version: {version}",
        )

    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()
