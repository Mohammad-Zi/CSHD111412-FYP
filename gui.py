
import tkinter as tk
from tkinter import ttk
import threading
import traceback
from datetime import datetime

from database import get_active_rules, get_ansible_hosts
from run_audit import run_audit


# ============================================================
# THEME
# ============================================================

BG = "#171717"
PANEL = "#222222"
PANEL_LIGHT = "#2B2B2B"
BORDER = "#3A3A3A"
FG = "#EEEEEE"
MUTED = "#A0A0A0"
WHITE = "#FFFFFF"
SUCCESS = "#BDBDBD"
WARNING = "#D0D0D0"
ERROR = "#F0F0F0"

FONT = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 10, "bold")
FONT_TITLE = ("Segoe UI", 19, "bold")
FONT_SUBTITLE = ("Segoe UI", 11)


# ============================================================
# ERROR TERMINAL
# ============================================================

class ErrorTerminal(tk.Toplevel):
    """Monochrome popup for errors and diagnostic output."""

    def __init__(self, parent):
        super().__init__(parent)

        self.withdraw()
        self.title("Diagnostic Terminal")
        self.geometry("720x430")
        self.minsize(520, 300)
        self.configure(bg=BG)
        self.transient(parent)

        header = tk.Frame(self, bg=PANEL, padx=16, pady=12)
        header.pack(fill="x")

        tk.Label(
            header,
            text="DIAGNOSTIC TERMINAL",
            bg=PANEL,
            fg=FG,
            font=FONT_BOLD,
        ).pack(side="left")

        tk.Button(
            header,
            text="Close",
            command=self.withdraw,
            bg=PANEL_LIGHT,
            fg=FG,
            activebackground=BORDER,
            activeforeground=WHITE,
            relief="flat",
            padx=12,
            pady=5,
            cursor="hand2",
        ).pack(side="right")

        self.output = tk.Text(
            self,
            bg="#101010",
            fg="#DDDDDD",
            insertbackground=WHITE,
            selectbackground="#555555",
            font=("Consolas", 10),
            relief="flat",
            wrap="word",
            padx=12,
            pady=12,
            state="disabled",
        )
        self.output.pack(fill="both", expand=True, padx=12, pady=12)

        self.withdraw()

    def show_error(self, title, details):
        """Display an error and its diagnostic details."""
        if threading.current_thread() is not threading.main_thread():
            self.after(
                0,
                lambda: self.show_error(title, details),
            )
            return

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        message = (
            f"[{timestamp}]\n"
            f"{title}\n"
            f"{'=' * 60}\n"
            f"{details}\n\n"
        )

        self.output.configure(state="normal")
        self.output.insert("end", message)
        self.output.see("end")
        self.output.configure(state="disabled")

        self.deiconify()
        self.lift()


# ============================================================
# MAIN APPLICATION
# ============================================================

class CISAuditApp(tk.Tk):

    def __init__(self):
        super().__init__()

        self.title("CIS Linux Security Audit")
        self.geometry("1280x800")
        self.minsize(1000, 650)
        self.configure(bg=BG)

        self.error_terminal = ErrorTerminal(self)

        self.vm_checks = {}
        self.vm_inventory = []
        self.audit_results = []
        self.active_rules = []
        self.selected_result = None
        self.audit_running = False

        self.vm_filter = tk.StringVar(value="All VMs")
        self.search_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Select a VM and run an audit.")

        self._configure_styles()
        self._build_layout()
        self._bind_events()

        self.load_rules()
        self.load_vm_inventory()

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # --------------------------------------------------------
    # STYLES
    # --------------------------------------------------------

    def _configure_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(
            "Treeview",
            background=PANEL,
            foreground=FG,
            fieldbackground=PANEL,
            bordercolor=BORDER,
            rowheight=30,
            font=FONT,
        )

        style.configure(
            "Treeview.Heading",
            background=PANEL_LIGHT,
            foreground=WHITE,
            relief="flat",
            font=FONT_BOLD,
            padding=8,
        )

        style.map(
            "Treeview",
            background=[("selected", "#454545")],
            foreground=[("selected", WHITE)],
        )

        style.configure(
            "Vertical.TScrollbar",
            background=PANEL_LIGHT,
            troughcolor=BG,
            bordercolor=BG,
            arrowcolor=FG,
        )

        style.configure(
            "Horizontal.TScrollbar",
            background=PANEL_LIGHT,
            troughcolor=BG,
            bordercolor=BG,
            arrowcolor=FG,
        )

    # --------------------------------------------------------
    # LAYOUT
    # --------------------------------------------------------

    def _build_layout(self):
        self._build_header()

        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=18, pady=(0, 12))

        body.grid_columnconfigure(0, minsize=260, weight=0)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        self.sidebar = tk.Frame(
            body,
            bg=PANEL,
            highlightbackground=BORDER,
            highlightthickness=1,
        )
        self.sidebar.grid(
            row=0,
            column=0,
            sticky="nsew",
            padx=(0, 12),
        )

        self.content = tk.Frame(body, bg=BG)
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(1, weight=1)

        self._build_sidebar()
        self._build_controls()
        self._build_results()
        self._build_statusbar()

    def _build_header(self):
        header = tk.Frame(self, bg=BG, padx=22, pady=18)
        header.pack(fill="x")

        title_area = tk.Frame(header, bg=BG)
        title_area.pack(side="left", fill="x", expand=True)

        tk.Label(
            title_area,
            text="CIS LINUX SECURITY AUDIT",
            bg=BG,
            fg=WHITE,
            font=FONT_TITLE,
        ).pack(anchor="w")

        tk.Label(
            title_area,
            text="Ubuntu security configuration assessment",
            bg=BG,
            fg=MUTED,
            font=FONT_SUBTITLE,
        ).pack(anchor="w", pady=(3, 0))

        tk.Button(
            header,
            text="View diagnostics",
            command=self._open_diagnostics,
            bg=PANEL,
            fg=FG,
            activebackground=PANEL_LIGHT,
            activeforeground=WHITE,
            relief="flat",
            padx=14,
            pady=9,
            cursor="hand2",
        ).pack(side="right", padx=(12, 0))

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", padx=18, pady=(0, 14))

    def _build_sidebar(self):
        tk.Label(
            self.sidebar,
            text="TARGET VIRTUAL MACHINES",
            bg=PANEL,
            fg=WHITE,
            font=FONT_BOLD,
        ).pack(anchor="w", padx=15, pady=(16, 5))

        tk.Label(
            self.sidebar,
            text="Choose one or more inventory hosts.",
            bg=PANEL,
            fg=MUTED,
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=15, pady=(0, 12))

        actions = tk.Frame(self.sidebar, bg=PANEL)
        actions.pack(fill="x", padx=12, pady=(0, 8))

        self.select_all_button = tk.Button(
            actions,
            text="Select all",
            command=self._toggle_all_vms,
            bg=PANEL_LIGHT,
            fg=FG,
            activebackground=BORDER,
            activeforeground=WHITE,
            relief="flat",
            padx=10,
            pady=6,
            cursor="hand2",
        )
        self.select_all_button.pack(side="left")

        self.refresh_vms_button = tk.Button(
            actions,
            text="Refresh",
            command=self.load_vm_inventory,
            bg=PANEL_LIGHT,
            fg=FG,
            activebackground=BORDER,
            activeforeground=WHITE,
            relief="flat",
            padx=10,
            pady=6,
            cursor="hand2",
        )
        self.refresh_vms_button.pack(side="right")

        self.vm_canvas = tk.Canvas(
            self.sidebar,
            bg=PANEL,
            highlightthickness=0,
            borderwidth=0,
        )
        self.vm_canvas.pack(
            fill="both",
            expand=True,
            padx=(10, 0),
            pady=(4, 12),
        )

        self.vm_scrollbar = ttk.Scrollbar(
            self.sidebar,
            orient="vertical",
            command=self.vm_canvas.yview,
        )
        self.vm_scrollbar.place(relx=1.0, rely=0.17, relheight=0.78, anchor="ne")

        self.vm_canvas.configure(yscrollcommand=self.vm_scrollbar.set)

        self.vm_row = tk.Frame(self.vm_canvas, bg=PANEL)
        self.vm_canvas_window = self.vm_canvas.create_window(
            (0, 0),
            window=self.vm_row,
            anchor="nw",
        )

        self.vm_row.bind(
            "<Configure>",
            lambda _event: self.vm_canvas.configure(
                scrollregion=self.vm_canvas.bbox("all")
            ),
        )

        self.vm_canvas.bind(
            "<Configure>",
            lambda event: self.vm_canvas.itemconfigure(
                self.vm_canvas_window,
                width=event.width,
            ),
        )

    def _build_controls(self):
        controls = tk.Frame(
            self.content,
            bg=PANEL,
            highlightbackground=BORDER,
            highlightthickness=1,
            padx=16,
            pady=14,
        )
        controls.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        controls.grid_columnconfigure(0, weight=1)

        tk.Label(
            controls,
            text="AUDIT CONTROLS",
            bg=PANEL,
            fg=WHITE,
            font=FONT_BOLD,
        ).grid(row=0, column=0, sticky="w")

        self.rule_count_label = tk.Label(
            controls,
            text="Active rules: 0",
            bg=PANEL,
            fg=MUTED,
            font=FONT,
        )
        self.rule_count_label.grid(row=0, column=1, sticky="e")

        tk.Label(
            controls,
            text="Search results",
            bg=PANEL,
            fg=MUTED,
            font=FONT,
        ).grid(row=1, column=0, sticky="w", pady=(16, 5))

        self.search_entry = tk.Entry(
            controls,
            textvariable=self.search_var,
            bg="#151515",
            fg=FG,
            insertbackground=WHITE,
            relief="flat",
            font=FONT,
        )
        self.search_entry.grid(
            row=2,
            column=0,
            sticky="ew",
            ipady=8,
            padx=(0, 12),
        )

        self.run_button = tk.Button(
            controls,
            text="▶   Run audit",
            command=self.execute_selected_audit,
            bg="#E0E0E0",
            fg="#111111",
            activebackground=WHITE,
            activeforeground="#111111",
            relief="flat",
            font=FONT_BOLD,
            padx=22,
            pady=9,
            cursor="hand2",
        )
        self.run_button.grid(row=2, column=1, sticky="e")

        self.rules_summary = tk.Label(
            controls,
            text="Rules will be loaded from the database.",
            bg=PANEL,
            fg=MUTED,
            font=("Segoe UI", 9),
            justify="left",
            anchor="w",
        )
        self.rules_summary.grid(
            row=3,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=(12, 0),
        )

    def _build_results(self):
        results_panel = tk.Frame(
            self.content,
            bg=PANEL,
            highlightbackground=BORDER,
            highlightthickness=1,
        )
        results_panel.grid(row=1, column=0, sticky="nsew")
        results_panel.grid_columnconfigure(0, weight=1)
        results_panel.grid_rowconfigure(1, weight=1)

        top = tk.Frame(results_panel, bg=PANEL, padx=15, pady=12)
        top.grid(row=0, column=0, sticky="ew")
        top.grid_columnconfigure(0, weight=1)

        tk.Label(
            top,
            text="AUDIT RESULTS",
            bg=PANEL,
            fg=WHITE,
            font=FONT_BOLD,
        ).grid(row=0, column=0, sticky="w")

        self.result_count_label = tk.Label(
            top,
            text="0 results",
            bg=PANEL,
            fg=MUTED,
            font=FONT,
        )
        self.result_count_label.grid(row=0, column=1, sticky="e")

        table_frame = tk.Frame(results_panel, bg=PANEL)
        table_frame.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 8))
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)

        columns = (
            "timestamp",
            "vm",
            "cis_id",
            "title",
            "command",
            "status",
        )

        self.results_tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        headings = {
            "timestamp": "TIME",
            "vm": "VIRTUAL MACHINE",
            "cis_id": "CIS ID",
            "title": "RULE",
            "command": "COMMAND / CHECK",
            "status": "STATUS",
        }

        widths = {
            "timestamp": 145,
            "vm": 125,
            "cis_id": 100,
            "title": 220,
            "command": 220,
            "status": 90,
        }

        for column in columns:
            self.results_tree.heading(column, text=headings[column])
            self.results_tree.column(
                column,
                width=widths[column],
                minwidth=65,
                anchor="w",
                stretch=(column in ("title", "command")),
            )

        vertical = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.results_tree.yview,
        )
        horizontal = ttk.Scrollbar(
            table_frame,
            orient="horizontal",
            command=self.results_tree.xview,
        )

        self.results_tree.configure(
            yscrollcommand=vertical.set,
            xscrollcommand=horizontal.set,
        )

        self.results_tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")

        self.results_tree.tag_configure("PASS", foreground="#F0F0F0")
        self.results_tree.tag_configure("FAIL", foreground="#AAAAAA")
        self.results_tree.tag_configure("ERROR", foreground="#FFFFFF")
        self.results_tree.tag_configure("REVIEW", foreground="#CCCCCC")

        detail_header = tk.Frame(results_panel, bg=PANEL, padx=15, pady=6)
        detail_header.grid(row=2, column=0, sticky="ew")

        tk.Label(
            detail_header,
            text="SELECTED RESULT DETAILS",
            bg=PANEL,
            fg=WHITE,
            font=FONT_BOLD,
        ).pack(anchor="w")

        self.detail_text = tk.Text(
            results_panel,
            height=6,
            bg="#151515",
            fg=FG,
            insertbackground=WHITE,
            relief="flat",
            font=("Consolas", 9),
            wrap="word",
            padx=12,
            pady=10,
            state="disabled",
        )
        self.detail_text.grid(
            row=3,
            column=0,
            sticky="ew",
            padx=12,
            pady=(0, 12),
        )

    def _build_statusbar(self):
        bar = tk.Frame(self, bg="#101010", padx=18, pady=8)
        bar.pack(fill="x", side="bottom")

        tk.Label(
            bar,
            textvariable=self.status_var,
            bg="#101010",
            fg=MUTED,
            font=("Segoe UI", 9),
            anchor="w",
        ).pack(fill="x")

    def _bind_events(self):
        self.search_var.trace_add("write", self._on_search_changed)
        self.results_tree.bind(
            "<<TreeviewSelect>>",
            self._on_result_selected,
        )

    # --------------------------------------------------------
    # INVENTORY
    # --------------------------------------------------------

    def load_vm_inventory(self):
        """Load VM targets from the Ansible inventory."""
        try:
            hosts = get_ansible_hosts()

            if not isinstance(hosts, (list, tuple)):
                raise TypeError(
                    "get_ansible_hosts() must return a list of host dictionaries."
                )

            self.vm_inventory = []

            for host in hosts:
                if isinstance(host, dict):
                    name = (
                        host.get("name")
                        or host.get("inventory_name")
                        or host.get("host")
                        or host.get("ansible_host")
                    )

                    if name:
                        self.vm_inventory.append(
                            {
                                "name": str(name),
                                "ansible_host": host.get("ansible_host", ""),
                                "ansible_user": host.get("ansible_user", ""),
                            }
                        )
                elif isinstance(host, str):
                    self.vm_inventory.append(
                        {
                            "name": host,
                            "ansible_host": "",
                            "ansible_user": "",
                        }
                    )

            self._render_vm_checkboxes()

            self.status_var.set(
                f"Inventory loaded: {len(self.vm_inventory)} host(s) available."
            )

        except Exception as exc:
            self.vm_inventory = []
            self._render_vm_checkboxes()

            self.status_var.set("Could not load Ansible inventory.")

            self.error_terminal.show_error(
                "Inventory loading error",
                f"{type(exc).__name__}: {exc}\n\n"
                f"{traceback.format_exc()}",
            )

    def _render_vm_checkboxes(self):
        for widget in self.vm_row.winfo_children():
            widget.destroy()

        self.vm_checks.clear()

        if not self.vm_inventory:
            tk.Label(
                self.vm_row,
                text="No inventory hosts found.",
                bg=PANEL,
                fg=MUTED,
                font=FONT,
                wraplength=210,
                justify="left",
            ).pack(anchor="w", padx=8, pady=12)
            return

        for host in self.vm_inventory:
            name = host["name"]
            variable = tk.BooleanVar(value=False)
            self.vm_checks[name] = variable

            row = tk.Frame(self.vm_row, bg=PANEL)
            row.pack(fill="x", padx=4, pady=4)

            checkbox = tk.Checkbutton(
                row,
                text=name,
                variable=variable,
                bg=PANEL,
                fg=FG,
                selectcolor=PANEL_LIGHT,
                activebackground=PANEL,
                activeforeground=WHITE,
                font=FONT,
                anchor="w",
                justify="left",
                wraplength=205,
                cursor="hand2",
            )
            checkbox.pack(fill="x", padx=5, pady=5)

            address = host.get("ansible_host")
            username = host.get("ansible_user")

            details = "  ·  ".join(
                str(value)
                for value in (address, username)
                if value
            )

            if details:
                tk.Label(
                    row,
                    text=details,
                    bg=PANEL,
                    fg=MUTED,
                    font=("Segoe UI", 8),
                    anchor="w",
                    wraplength=210,
                ).pack(anchor="w", padx=(29, 5), pady=(0, 4))

        self.vm_canvas.configure(
            scrollregion=self.vm_canvas.bbox("all")
        )

    def _toggle_all_vms(self):
        if not self.vm_checks:
            self.error_terminal.show_error(
                "No inventory hosts",
                "No hosts are available to select. Refresh the inventory "
                "and check the Ansible inventory configuration.",
            )
            return

        select_all = not all(
            variable.get()
            for variable in self.vm_checks.values()
        )

        for variable in self.vm_checks.values():
            variable.set(select_all)

        self.select_all_button.configure(
            text="Deselect all" if select_all else "Select all"
        )

    # --------------------------------------------------------
    # RULES
    # --------------------------------------------------------

    def load_rules(self):
        """Load active CIS rules from the database."""
        try:
            rules = get_active_rules()

            if rules is None:
                rules = []

            self.active_rules = list(rules)

            self.rule_count_label.configure(
                text=f"Active rules: {len(self.active_rules)}"
            )

            if not self.active_rules:
                self.rules_summary.configure(
                    text="No active rules were returned by the database."
                )
            else:
                names = []

                for rule in self.active_rules[:5]:
                    if isinstance(rule, dict):
                        names.append(
                            str(
                                rule.get("cis_id")
                                or rule.get("rule_id")
                                or rule.get("title")
                                or "Unnamed rule"
                            )
                        )
                    else:
                        names.append(str(rule))

                summary = "   •   ".join(names)

                if len(self.active_rules) > 5:
                    summary += f"   •   +{len(self.active_rules) - 5} more"

                self.rules_summary.configure(text=summary)

        except Exception as exc:
            self.active_rules = []
            self.rule_count_label.configure(text="Active rules: unavailable")
            self.rules_summary.configure(
                text="Could not load rules. See diagnostics."
            )

            self.error_terminal.show_error(
                "Rule loading error",
                f"{type(exc).__name__}: {exc}\n\n"
                f"{traceback.format_exc()}",
            )

    # --------------------------------------------------------
    # RUN AUDIT
    # --------------------------------------------------------

    def execute_selected_audit(self):
        """Start auditing selected VMs in a background thread."""
        if self.audit_running:
            return

        selected_vms = [
            name
            for name, variable in self.vm_checks.items()
            if variable.get()
        ]

        if not selected_vms:
            self.error_terminal.show_error(
                "No VM selected",
                "Select at least one VM before running the audit.",
            )
            return

        self.audit_running = True
        self.run_button.configure(
            state="disabled",
            text="Running audit...",
        )
        self.refresh_vms_button.configure(state="disabled")
        self.status_var.set(
            f"Audit running against {len(selected_vms)} selected VM(s)..."
        )

        self._clear_details()

        def worker():
            all_results = []
            errors = []

            for vm_name in selected_vms:
                try:
                    print(f"[Audit] Starting: {vm_name}", flush=True)

                    results = run_audit(vm_name)

                    if results is None:
                        results = []

                    if isinstance(results, dict):
                        results = [results]

                    if not isinstance(results, (list, tuple)):
                        raise TypeError(
                            "run_audit(vm_name) must return a list of result dictionaries."
                        )

                    for result in results:
                        if not isinstance(result, dict):
                            result = {
                                "status": "ERROR",
                                "actual": str(result),
                            }

                        result.setdefault("vm", vm_name)
                        result.setdefault(
                            "timestamp",
                            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        )

                        all_results.append(result)

                    print(f"[Audit] Finished: {vm_name}", flush=True)

                except Exception as exc:
                    error_details = (
                        f"VM: {vm_name}\n"
                        f"{type(exc).__name__}: {exc}\n\n"
                        f"{traceback.format_exc()}"
                    )
                    errors.append(error_details)
                    print(error_details, flush=True)

            try:
                self.after(
                    0,
                    lambda results=all_results, failures=errors:
                    self._finish_audit(results, failures),
                )
            except Exception as exc:
                print(
                    f"Could not schedule GUI update: {exc}",
                    flush=True,
                )

        threading.Thread(
            target=worker,
            name="CIS-Audit-Worker",
            daemon=True,
        ).start()

    def _finish_audit(self, results, errors):
        """Display audit results on the Tkinter main thread."""
        try:
            self.audit_results = results
            self.refresh_results_table()

            if errors:
                self.error_terminal.show_error(
                    "Audit execution errors",
                    "\n\n".join(errors),
                )

            if not results and not errors:
                self.error_terminal.show_error(
                    "No audit results",
                    "The audit returned no results and no execution errors.\n\n"
                    "Check run_audit.py, the database audit commands, and "
                    "the Ansible task output.",
                )

            if results:
                self.status_var.set(
                    f"Audit completed. {len(results)} result(s) returned "
                    f"for {len({r.get('vm', '') for r in results})} VM(s)."
                )
            elif errors:
                self.status_var.set(
                    "Audit finished with errors. Open diagnostics for details."
                )
            else:
                self.status_var.set("Audit completed without returned results.")

        except Exception as exc:
            self.error_terminal.show_error(
                "Results display error",
                f"{type(exc).__name__}: {exc}\n\n"
                f"{traceback.format_exc()}",
            )

        finally:
            self.audit_running = False
            self.run_button.configure(
                state="normal",
                text="▶   Run audit",
            )
            self.refresh_vms_button.configure(state="normal")

    # --------------------------------------------------------
    # RESULTS TABLE
    # --------------------------------------------------------

    def refresh_results_table(self):
        """Refresh the results table using the current search filter."""
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        query = self.search_var.get().strip().lower()
        visible_count = 0

        for index, result in enumerate(self.audit_results):
            if not isinstance(result, dict):
                continue

            timestamp = str(
                result.get("timestamp")
                or result.get("executed_at")
                or ""
            )

            vm = str(
                result.get("vm")
                or result.get("host")
                or result.get("hostname")
                or ""
            )

            cis_id = str(
                result.get("cis_id")
                or result.get("rule_id")
                or ""
            )

            title = str(
                result.get("title")
                or result.get("rule_title")
                or result.get("description")
                or ""
            )

            command = str(
                result.get("command")
                or result.get("command_type")
                or result.get("check")
                or ""
            )

            status = str(result.get("status") or "REVIEW").upper()

            searchable = " ".join(
                (timestamp, vm, cis_id, title, command, status,
                 str(result.get("actual", "")),
                 str(result.get("expected", "")))
            ).lower()

            if query and query not in searchable:
                continue

            tag = status if status in (
                "PASS", "FAIL", "ERROR", "REVIEW"
            ) else "REVIEW"

            self.results_tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    timestamp,
                    vm,
                    cis_id,
                    title,
                    command,
                    status,
                ),
                tags=(tag,),
            )

            visible_count += 1

        self.result_count_label.configure(
            text=f"{visible_count} result(s)"
        )

    def _on_search_changed(self, *_args):
        self.refresh_results_table()

    def _on_result_selected(self, _event=None):
        selected = self.results_tree.selection()

        if not selected:
            self.selected_result = None
            self._clear_details()
            return

        try:
            index = int(selected[0])
            result = self.audit_results[index]
            self.selected_result = result

            details = [
                f"VM: {result.get('vm', result.get('host', ''))}",
                f"CIS ID: {result.get('cis_id', result.get('rule_id', ''))}",
                f"Rule: {result.get('title', result.get('rule_title', ''))}",
                f"Status: {result.get('status', 'REVIEW')}",
                f"Command: {result.get('command', '')}",
                f"Expected: {result.get('expected', '')}",
                f"Actual: {result.get('actual', '')}",
                f"Details: {result.get('details', result.get('message', ''))}",
            ]

            self.detail_text.configure(state="normal")
            self.detail_text.delete("1.0", "end")
            self.detail_text.insert("1.0", "\n".join(details))
            self.detail_text.configure(state="disabled")

        except (ValueError, IndexError, tk.TclError) as exc:
            self.error_terminal.show_error(
                "Result selection error",
                f"{type(exc).__name__}: {exc}",
            )

    def _clear_details(self):
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert(
            "1.0",
            "Select a result above to view its expected and actual output.",
        )
        self.detail_text.configure(state="disabled")

    # --------------------------------------------------------
    # UTILITIES
    # --------------------------------------------------------

    def _open_diagnostics(self):
        self.error_terminal.deiconify()
        self.error_terminal.lift()

    def _on_close(self):
        if self.audit_running:
            self.error_terminal.show_error(
                "Audit still running",
                "An audit is still executing in the background. "
                "Wait for it to finish before closing the application.",
            )
            return

        self.destroy()


# ============================================================
# APPLICATION ENTRY POINT
# ============================================================

if __name__ == "__main__":
    app = CISAuditApp()
    app.mainloop()
