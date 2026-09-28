from __future__ import annotations

import copy
import tkinter as tk
from tkinter import messagebox, ttk

try:
    import customtkinter as ctk
except Exception:  # pragma: no cover - optional runtime dependency
    ctk = None

from .network_utils import ip_exists_locally, iter_local_ipv4_addresses, validate_ipv4, validate_prefix


class SimulatorGUI:
    def __init__(self, controller) -> None:
        self.controller = controller
        self.using_ctk = ctk is not None
        self.root = None
        self.tabs = {}
        self.metrics_labels: dict[str, object] = {}
        self.summary_labels: dict[str, object] = {}
        self.detail_labels: dict[str, object] = {}
        self.config_entries: dict[str, tk.StringVar] = {}
        self.interface_vars: dict[str, tk.Variable] = {}
        self.tree_items: dict[str, tuple] = {}
        self.interface_index_names: dict[int, str] = {}
        self.log_text = None
        self.dashboard_events_text = None
        self.dashboard_story_text = None
        self.snmp_info_text = None
        self.syslog_info_text = None
        self.stp_info_text = None
        self.protocol_status_labels: dict[str, object] = {}
        self.interface_tree = None
        self._log_history: list[str] = []
        self._dashboard_history: list[str] = []

    def build(self):
        if self.using_ctk:
            ctk.set_appearance_mode("dark")
            ctk.set_default_color_theme("blue")
            self.root = ctk.CTk()
            self.root.title("NetGuard Switch Simulator")
            self.root.geometry("1600x980")
            self.root.minsize(1380, 860)
            self._build_ctk()
        else:
            self.root = tk.Tk()
            self.root.title("NetGuard Switch Simulator")
            self.root.geometry("1600x980")
            self.root.minsize(1380, 860)
            self.root.configure(bg="#10141b")
            self._build_ttk()
        self.root.protocol("WM_DELETE_WINDOW", self.controller.on_close)
        return self.root

    def _build_ctk(self) -> None:
        root = self.root
        root.grid_columnconfigure(0, weight=1)
        root.grid_rowconfigure(2, weight=1)

        header = ctk.CTkFrame(root, fg_color="#111827", corner_radius=18)
        header.grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 10))
        header.grid_columnconfigure(0, weight=1)
        header.grid_columnconfigure(1, weight=0)
        self._build_header(header)

        status = ctk.CTkFrame(root, fg_color="#0f172a", corner_radius=18)
        status.grid(row=1, column=0, sticky="ew", padx=18, pady=(0, 10))
        for index in range(6):
            status.grid_columnconfigure(index, weight=1)
        self._build_metric_strip(status)

        tabs = ctk.CTkTabview(root, corner_radius=16, segmented_button_fg_color="#1f2937", segmented_button_selected_color="#2563eb")
        tabs.grid(row=2, column=0, sticky="nsew", padx=18, pady=(0, 18))
        for name in ("Dashboard", "Interfaces", "STP", "SNMP", "Syslog", "Eventos / Logs", "Configuracao"):
            self.tabs[name] = tabs.add(name)
        self._build_all_tabs()

    def _build_ttk(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", background="#10141b", foreground="#e5eefc", fieldbackground="#17202b")
        style.configure("Treeview", background="#17202b", foreground="#e5eefc", fieldbackground="#17202b", rowheight=28)
        style.configure("Treeview.Heading", background="#1f2937", foreground="#f8fafc")
        style.map("Treeview", background=[("selected", "#1d4ed8")])

        main = ttk.Frame(self.root)
        main.pack(fill="both", expand=True, padx=16, pady=16)
        header = ttk.Frame(main)
        header.pack(fill="x")
        self._build_header(header)
        status = ttk.Frame(main)
        status.pack(fill="x", pady=(10, 10))
        self._build_metric_strip(status)
        notebook = ttk.Notebook(main)
        notebook.pack(fill="both", expand=True)
        for name in ("Dashboard", "Interfaces", "STP", "SNMP", "Syslog", "Eventos / Logs", "Configuracao"):
            frame = ttk.Frame(notebook)
            notebook.add(frame, text=name)
            self.tabs[name] = frame
        self._build_all_tabs()

    def _build_all_tabs(self) -> None:
        self._build_dashboard_tab(self.tabs["Dashboard"])
        self._build_interfaces_tab(self.tabs["Interfaces"])
        self._build_stp_tab(self.tabs["STP"])
        self._build_snmp_tab(self.tabs["SNMP"])
        self._build_syslog_tab(self.tabs["Syslog"])
        self._build_logs_tab(self.tabs["Eventos / Logs"])
        self._build_config_tab(self.tabs["Configuracao"])

    def _frame(self, parent, **kwargs):
        if self.using_ctk:
            return ctk.CTkFrame(parent, **kwargs)
        kwargs.pop("fg_color", None)
        kwargs.pop("corner_radius", None)
        return ttk.Frame(parent)

    def _label(self, parent, text: str, **kwargs):
        if self.using_ctk:
            return ctk.CTkLabel(parent, text=text, **kwargs)
        return ttk.Label(parent, text=text)

    def _button(self, parent, text: str, command, **kwargs):
        if self.using_ctk:
            return ctk.CTkButton(parent, text=text, command=command, **kwargs)
        return ttk.Button(parent, text=text, command=command)

    def _entry(self, parent, textvariable=None, width=160):
        if self.using_ctk:
            return ctk.CTkEntry(parent, textvariable=textvariable, width=width)
        return ttk.Entry(parent, textvariable=textvariable, width=max(12, width // 10))

    def _textbox(self, parent, **kwargs):
        if self.using_ctk:
            return ctk.CTkTextbox(parent, **kwargs)
        return tk.Text(parent, bg="#0f172a", fg="#e5eefc", insertbackground="#e5eefc", relief="flat", **kwargs)

    def _check(self, parent, text: str, variable):
        if self.using_ctk:
            return ctk.CTkCheckBox(parent, text=text, variable=variable, onvalue=True, offvalue=False)
        return ttk.Checkbutton(parent, text=text, variable=variable)

    def _combo(self, parent, variable, values, width=140):
        if self.using_ctk:
            return ctk.CTkComboBox(parent, variable=variable, values=values, width=width, state="readonly")
        return ttk.Combobox(parent, textvariable=variable, values=values, width=max(10, width // 10), state="readonly")

    def _section_card(self, parent, title: str, subtitle: str | None = None):
        frame = self._frame(parent, fg_color="#111827" if self.using_ctk else None, corner_radius=18 if self.using_ctk else None)
        if self.using_ctk:
            self._label(frame, title, font=("Segoe UI Semibold", 18), text_color="#f8fafc").pack(anchor="w", padx=16, pady=(14, 2))
            if subtitle:
                self._label(frame, subtitle, font=("Segoe UI", 12), text_color="#94a3b8").pack(anchor="w", padx=16, pady=(0, 12))
        else:
            ttk.Label(frame, text=title, font=("Segoe UI Semibold", 14)).pack(anchor="w", padx=12, pady=(10, 2))
            if subtitle:
                ttk.Label(frame, text=subtitle).pack(anchor="w", padx=12, pady=(0, 10))
        return frame

    def _set_textbox(self, widget, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", text)
        widget.configure(state="disabled")

    def _append_textbox_lines(self, widget, history: list[str], lines: list[str], limit: int) -> None:
        if not widget or not lines:
            return
        history.extend(lines)
        if len(history) > limit:
            del history[:-limit]
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", "\n".join(history))
        widget.see("end")
        widget.configure(state="disabled")

    def _build_header(self, parent) -> None:
        left = self._frame(parent, fg_color="transparent" if self.using_ctk else None)
        right = self._frame(parent, fg_color="transparent" if self.using_ctk else None)
        if self.using_ctk:
            left.grid(row=0, column=0, sticky="w", padx=18, pady=16)
            right.grid(row=0, column=1, sticky="e", padx=18, pady=16)
            self._label(left, "NetGuard Switch Simulator", font=("Segoe UI Semibold", 28), text_color="#f8fafc").pack(anchor="w")
            self._label(left, "Switch L2/L3 simulado para validar SNMP, syslog, STP, loops, flap, degradacao e rastreabilidade.", font=("Segoe UI", 13), text_color="#9fb0c7").pack(anchor="w", pady=(4, 0))
        else:
            left.pack(side="left", fill="x", expand=True, padx=8, pady=8)
            right.pack(side="right", padx=8, pady=8)
            ttk.Label(left, text="NetGuard Switch Simulator", font=("Segoe UI Semibold", 20)).pack(anchor="w")
            ttk.Label(left, text="Laboratorio visual para testes de monitoramento e incidentes.").pack(anchor="w")

        banner = self._section_card(right, "Aviso de Laboratorio", "O simulador nao cria interface real no Windows.")
        banner.pack(fill="both", expand=True)
        self.summary_labels["bind_warning"] = self._label(
            banner,
            "Ping, SNMP e syslog so funcionam plenamente se o IP de gerencia existir localmente.",
            font=("Segoe UI", 12),
            text_color="#fbbf24" if self.using_ctk else None,
            justify="left",
        )
        self.summary_labels["bind_warning"].pack(anchor="w", padx=16 if self.using_ctk else 12, pady=(0, 14 if self.using_ctk else 10))

    def _build_metric_strip(self, parent) -> None:
        metrics = [
            ("snmp_status", "SNMP"),
            ("management_ip", "IP de Gerencia"),
            ("interfaces", "Interfaces"),
            ("loops_active", "Loops"),
            ("total_errors", "Erros"),
            ("tc_count", "TC Count"),
        ]
        for index, (key, title) in enumerate(metrics):
            card = self._frame(parent, fg_color="#1e293b" if self.using_ctk else None, corner_radius=16 if self.using_ctk else None)
            if self.using_ctk:
                card.grid(row=0, column=index, sticky="nsew", padx=8, pady=8)
            else:
                card.pack(side="left", fill="both", expand=True, padx=4, pady=4)
            self._label(card, title, font=("Segoe UI", 12), text_color="#93c5fd" if self.using_ctk else None).pack(anchor="w", padx=14, pady=(12, 2))
            value = self._label(card, "--", font=("Segoe UI Semibold", 20), text_color="#f8fafc" if self.using_ctk else None)
            value.pack(anchor="w", padx=14, pady=(0, 12))
            self.metrics_labels[key] = value

    def _build_dashboard_tab(self, parent) -> None:
        if self.using_ctk:
            parent.grid_columnconfigure(0, weight=3)
            parent.grid_columnconfigure(1, weight=2)
            parent.grid_rowconfigure(0, weight=0)
            parent.grid_rowconfigure(1, weight=1)
        else:
            parent.columnconfigure(0, weight=3)
            parent.columnconfigure(1, weight=2)
            parent.rowconfigure(1, weight=1)

        hero = self._section_card(parent, "Centro de Comando", "Acione testes comuns sem procurar cada funcao pela interface.")
        quick = self._section_card(parent, "Cenarios Rapidos", "Atalhos para validar loop, flap, erros, STP e recuperacao.")
        health = self._section_card(parent, "Resumo Operacional", "Leitura rapida do estado atual do equipamento simulado.")
        events = self._section_card(parent, "Eventos Recentes", "Ultimos sinais gerados pelo simulador.")

        hero.grid(row=0, column=0, sticky="nsew", padx=(14, 8), pady=(14, 8))
        quick.grid(row=0, column=1, sticky="nsew", padx=(8, 14), pady=(14, 8))
        health.grid(row=1, column=0, sticky="nsew", padx=(14, 8), pady=(8, 14))
        events.grid(row=1, column=1, sticky="nsew", padx=(8, 14), pady=(8, 14))

        self.dashboard_story_text = self._textbox(hero, height=160)
        self.dashboard_story_text.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self._set_textbox(
            self.dashboard_story_text,
            "Objetivo\n"
            "- Use esta tela para disparar testes rapidamente.\n"
            "- A aba Interfaces mostra a superficie detalhada do incidente.\n"
            "- As abas SNMP e Syslog ajudam a confirmar a telemetria de saida.\n\n"
            "Fluxo sugerido\n"
            "1. Valide o IP de gerencia.\n"
            "2. Acione um cenario.\n"
            "3. Observe a porta e os logs.\n"
            "4. Verifique se o NetGuard correlacionou o incidente.\n",
        )

        actions = self._frame(quick, fg_color="transparent" if self.using_ctk else None)
        actions.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        action_specs = [
            ("Validar IP Local", self.controller.validate_management_ip),
            ("Admin Down na Porta", lambda: self.controller.set_selected_admin(False)),
            ("Admin Up na Porta", lambda: self.controller.set_selected_admin(True)),
            ("Burst de Erros", self.controller.trigger_selected_error_burst),
            ("Discards", self.controller.trigger_selected_discards),
            ("Storm ON/OFF", self.controller.toggle_selected_storm),
            ("Flap ON/OFF", self.controller.toggle_selected_flap),
            ("Err-Disable", self.controller.toggle_selected_errdisable),
            ("Loop Protegido", self.controller.simulate_protected_loop),
            ("Loop sem Bloqueio", self.controller.simulate_unprotected_loop),
            ("Disparar TCN", self.controller.trigger_tcn),
            ("Limpar Loops", self.controller.clear_loops),
        ]
        for index, (label, command) in enumerate(action_specs):
            button = self._button(actions, label, command, fg_color="#2563eb" if self.using_ctk else None, hover_color="#1d4ed8" if self.using_ctk else None, height=38 if self.using_ctk else None)
            button.grid(row=index // 2, column=index % 2, sticky="ew", padx=6, pady=6)
            actions.grid_columnconfigure(index % 2, weight=1)

        health_grid = self._frame(health, fg_color="transparent" if self.using_ctk else None)
        health_grid.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        detail_specs = [
            ("hostname", "Hostname"),
            ("gateway", "Gateway"),
            ("uptime", "Uptime"),
            ("snmp_queries", "Queries SNMP"),
            ("traps_sent", "Traps"),
            ("syslog_sent", "Syslog"),
            ("root_bridge_id", "Root Bridge"),
            ("stp_mode", "Modo STP"),
        ]
        for index, (key, title) in enumerate(detail_specs):
            cell = self._frame(health_grid, fg_color="#0f172a" if self.using_ctk else None, corner_radius=14 if self.using_ctk else None)
            cell.grid(row=index // 2, column=index % 2, sticky="nsew", padx=6, pady=6)
            health_grid.grid_columnconfigure(index % 2, weight=1)
            self._label(cell, title, font=("Segoe UI", 11), text_color="#93c5fd" if self.using_ctk else None).pack(anchor="w", padx=12, pady=(10, 2))
            value = self._label(cell, "--", font=("Segoe UI Semibold", 16), text_color="#f8fafc" if self.using_ctk else None, wraplength=320 if self.using_ctk else None, justify="left")
            value.pack(anchor="w", padx=12, pady=(0, 10))
            self.detail_labels[key] = value

        self.dashboard_events_text = self._textbox(events, height=420)
        self.dashboard_events_text.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self._set_textbox(self.dashboard_events_text, "Os eventos mais recentes aparecerao aqui conforme os testes forem executados.")

    def _build_interfaces_tab(self, parent) -> None:
        if self.using_ctk:
            parent.grid_columnconfigure(0, weight=0)
            parent.grid_columnconfigure(1, weight=1)
            parent.grid_rowconfigure(0, weight=1)
        else:
            parent.columnconfigure(0, weight=0)
            parent.columnconfigure(1, weight=1)
            parent.rowconfigure(0, weight=1)

        side = self._section_card(parent, "Laboratorio de Porta", "Selecione a interface e aplique perturbacoes controladas.")
        main = self._section_card(parent, "Mapa de Interfaces", "Tabela viva com atualizacao diferencial e leitura de estado realista.")
        side.grid(row=0, column=0, sticky="ns", padx=(14, 8), pady=14)
        main.grid(row=0, column=1, sticky="nsew", padx=(8, 14), pady=14)

        self.interface_vars["selected_if"] = tk.StringVar(value="Gi0/1")
        self.interface_vars["flap_interval"] = tk.StringVar(value="10")
        self.interface_vars["loop_a"] = tk.StringVar(value="Gi0/1")
        self.interface_vars["loop_b"] = tk.StringVar(value="Gi0/2")

        picker = self._frame(side, fg_color="#0f172a" if self.using_ctk else None, corner_radius=14 if self.using_ctk else None)
        picker.pack(fill="x", padx=16, pady=(0, 12))
        self._label(picker, "Interface alvo", font=("Segoe UI", 12), text_color="#93c5fd" if self.using_ctk else None).pack(anchor="w", padx=12, pady=(12, 4))
        self.interface_selector = self._combo(picker, self.interface_vars["selected_if"], ["Gi0/1"], width=220)
        self.interface_selector.pack(anchor="w", padx=12, pady=(0, 10))
        self._label(picker, "Intervalo de flap (s)", font=("Segoe UI", 12), text_color="#93c5fd" if self.using_ctk else None).pack(anchor="w", padx=12, pady=(6, 4))
        self._entry(picker, self.interface_vars["flap_interval"], width=120).pack(anchor="w", padx=12, pady=(0, 12))

        operations = self._frame(side, fg_color="transparent" if self.using_ctk else None)
        operations.pack(fill="x", padx=16, pady=(0, 12))
        ops = [
            ("Admin Down", lambda: self.controller.set_selected_admin(False)),
            ("Admin Up", lambda: self.controller.set_selected_admin(True)),
            ("Burst de Erros", self.controller.trigger_selected_error_burst),
            ("Discards", self.controller.trigger_selected_discards),
            ("Storm ON/OFF", self.controller.toggle_selected_storm),
            ("Flap ON/OFF", self.controller.toggle_selected_flap),
            ("Err-Disable", self.controller.toggle_selected_errdisable),
        ]
        for label, command in ops:
            button = self._button(operations, label, command, fg_color="#1d4ed8" if self.using_ctk else None, hover_color="#1e40af" if self.using_ctk else None, height=36 if self.using_ctk else None)
            button.pack(fill="x", pady=4)

        loop_box = self._frame(side, fg_color="#0f172a" if self.using_ctk else None, corner_radius=14 if self.using_ctk else None)
        loop_box.pack(fill="x", padx=16, pady=(0, 12))
        self._label(loop_box, "Teste de loop", font=("Segoe UI", 12), text_color="#93c5fd" if self.using_ctk else None).pack(anchor="w", padx=12, pady=(12, 8))
        loops_line = self._frame(loop_box, fg_color="transparent" if self.using_ctk else None)
        loops_line.pack(fill="x", padx=12, pady=(0, 8))
        self.loop_a_selector = self._combo(loops_line, self.interface_vars["loop_a"], ["Gi0/1"], width=90)
        self.loop_b_selector = self._combo(loops_line, self.interface_vars["loop_b"], ["Gi0/2"], width=90)
        self.loop_a_selector.pack(side="left", padx=(0, 8))
        self.loop_b_selector.pack(side="left")
        self._button(loop_box, "Simular Loop Protegido", self.controller.simulate_protected_loop, fg_color="#0f766e" if self.using_ctk else None).pack(fill="x", padx=12, pady=4)
        self._button(loop_box, "Simular Loop sem Bloqueio", self.controller.simulate_unprotected_loop, fg_color="#b45309" if self.using_ctk else None).pack(fill="x", padx=12, pady=4)
        self._button(loop_box, "Limpar Loops", self.controller.clear_loops, fg_color="#374151" if self.using_ctk else None).pack(fill="x", padx=12, pady=(4, 12))

        detail_box = self._frame(side, fg_color="#0f172a" if self.using_ctk else None, corner_radius=14 if self.using_ctk else None)
        detail_box.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self._label(detail_box, "Resumo da interface", font=("Segoe UI", 12), text_color="#93c5fd" if self.using_ctk else None).pack(anchor="w", padx=12, pady=(12, 8))
        for key, title in (("selected_name", "Porta"), ("selected_link", "Link"), ("selected_mode", "Modo"), ("selected_vlan", "VLAN"), ("selected_stp", "STP"), ("selected_counters", "Contadores")):
            line = self._frame(detail_box, fg_color="transparent" if self.using_ctk else None)
            line.pack(fill="x", padx=12, pady=2)
            self._label(line, f"{title}:", font=("Segoe UI", 11), text_color="#94a3b8" if self.using_ctk else None).pack(anchor="w")
            value = self._label(line, "--", font=("Segoe UI Semibold", 13), text_color="#f8fafc" if self.using_ctk else None, wraplength=260 if self.using_ctk else None, justify="left")
            value.pack(anchor="w", pady=(0, 4))
            self.detail_labels[key] = value

        table_wrap = self._frame(main, fg_color="transparent" if self.using_ctk else None)
        table_wrap.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        columns = ("name", "admin", "oper", "mode", "vlan", "speed", "duplex", "stp_state", "stp_role", "in_octets", "out_octets", "errors", "discards", "loop", "desc")
        tree = ttk.Treeview(table_wrap, columns=columns, show="headings")
        headers = {
            "name": "Interface",
            "admin": "Admin",
            "oper": "Oper",
            "mode": "Modo",
            "vlan": "VLAN",
            "speed": "Speed",
            "duplex": "Duplex",
            "stp_state": "STP State",
            "stp_role": "STP Role",
            "in_octets": "In Octets",
            "out_octets": "Out Octets",
            "errors": "Erros",
            "discards": "Discards",
            "loop": "Loop",
            "desc": "Descricao",
        }
        widths = {"name": 90, "admin": 70, "oper": 70, "mode": 80, "vlan": 70, "speed": 90, "duplex": 80, "stp_state": 100, "stp_role": 100, "in_octets": 120, "out_octets": 120, "errors": 90, "discards": 90, "loop": 70, "desc": 200}
        for column in columns:
            tree.heading(column, text=headers[column])
            tree.column(column, width=widths[column], stretch=column in {"desc", "in_octets", "out_octets"})
        scrollbar = ttk.Scrollbar(table_wrap, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.interface_tree = tree

    def _build_stp_tab(self, parent) -> None:
        if self.using_ctk:
            parent.grid_columnconfigure(0, weight=1)
            parent.grid_columnconfigure(1, weight=1)
            parent.grid_rowconfigure(1, weight=1)
        else:
            parent.columnconfigure(0, weight=1)
            parent.columnconfigure(1, weight=1)
            parent.rowconfigure(1, weight=1)

        controls = self._section_card(parent, "Controles de Topologia", "Ajuste o comportamento do STP e simule reacoes de topologia.")
        loops = self._section_card(parent, "Comportamento de Loop", "Mantenha o STP ligado, desligue a contencao automatica ou force um teste protegido.")
        summary = self._section_card(parent, "Resumo de STP", "Indicadores uteis para explicar o que o NetGuard deve detectar.")
        notes = self._section_card(parent, "Guia de Teste", "Passo a passo rapido para incidentes com e sem bloqueio.")

        controls.grid(row=0, column=0, sticky="nsew", padx=(14, 8), pady=(14, 8))
        loops.grid(row=0, column=1, sticky="nsew", padx=(8, 14), pady=(14, 8))
        summary.grid(row=1, column=0, sticky="nsew", padx=(14, 8), pady=(8, 14))
        notes.grid(row=1, column=1, sticky="nsew", padx=(8, 14), pady=(8, 14))

        self.interface_vars["stp_enabled"] = tk.BooleanVar(value=True)
        self.interface_vars["loop_guard_enabled"] = tk.BooleanVar(value=True)
        self.interface_vars["auto_block_on_loop"] = tk.BooleanVar(value=True)

        checks = self._frame(controls, fg_color="transparent" if self.using_ctk else None)
        checks.pack(fill="x", padx=16, pady=(0, 16))
        self._check(checks, "STP ON", self.interface_vars["stp_enabled"]).pack(anchor="w", pady=4)
        self._check(checks, "Loop Guard ON", self.interface_vars["loop_guard_enabled"]).pack(anchor="w", pady=4)
        self._check(checks, "Acao Automatica do STP", self.interface_vars["auto_block_on_loop"]).pack(anchor="w", pady=4)
        self._button(controls, "Aplicar Modo STP", self.controller.apply_stp_modes, fg_color="#1d4ed8" if self.using_ctk else None).pack(fill="x", padx=16, pady=4)
        self._button(controls, "Disparar TCN", self.controller.trigger_tcn, fg_color="#0f766e" if self.using_ctk else None).pack(fill="x", padx=16, pady=4)
        self._button(controls, "Reeleger Root", self.controller.reelect_root, fg_color="#7c3aed" if self.using_ctk else None).pack(fill="x", padx=16, pady=4)
        self._button(controls, "Limpar Loops", self.controller.clear_loops, fg_color="#374151" if self.using_ctk else None).pack(fill="x", padx=16, pady=(4, 16))

        box = self._textbox(loops, height=230)
        box.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self._set_textbox(
            box,
            "Loop protegido\n"
            "- STP ON\n"
            "- Loop Guard ON\n"
            "- Acao automatica ON\n\n"
            "Loop sem bloqueio\n"
            "- STP pode permanecer ON\n"
            "- Desligue a acao automatica do STP\n"
            "- O simulador vai manter sintomas ativos para o NetGuard observar\n",
        )

        for key, title in (("stp_state", "Estado global"), ("stp_root", "Root bridge"), ("stp_tc", "Topology changes"), ("stp_loops", "Loops ativos")):
            panel = self._frame(summary, fg_color="#0f172a" if self.using_ctk else None, corner_radius=14 if self.using_ctk else None)
            panel.pack(fill="x", padx=16, pady=6)
            self._label(panel, title, font=("Segoe UI", 11), text_color="#93c5fd" if self.using_ctk else None).pack(anchor="w", padx=12, pady=(10, 2))
            value = self._label(panel, "--", font=("Segoe UI Semibold", 15), text_color="#f8fafc" if self.using_ctk else None, wraplength=420 if self.using_ctk else None, justify="left")
            value.pack(anchor="w", padx=12, pady=(0, 10))
            self.detail_labels[key] = value

        self.stp_info_text = self._textbox(notes, height=320)
        self.stp_info_text.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self._set_textbox(
            self.stp_info_text,
            "Roteiro sugerido\n"
            "1. Inicie com STP ON e acione um loop protegido.\n"
            "2. Verifique bloqueio, traps de topologia e syslogs de SPANTREE.\n"
            "3. Em seguida desligue a acao automatica do STP.\n"
            "4. Aplique um loop sem bloqueio para observar storm, discards e MAC flapping.\n"
            "5. Limpe os loops para encerrar o incidente.\n",
        )

    def _build_snmp_tab(self, parent) -> None:
        if self.using_ctk:
            parent.grid_columnconfigure(0, weight=1)
            parent.grid_columnconfigure(1, weight=1)
            parent.grid_rowconfigure(1, weight=1)
        else:
            parent.columnconfigure(0, weight=1)
            parent.columnconfigure(1, weight=1)
            parent.rowconfigure(1, weight=1)

        status = self._section_card(parent, "Status do Agente", "Confirme bind, community e visibilidade dos OIDs principais.")
        config = self._section_card(parent, "Pontos de Coleta", "Resumo rapido do que consultar no NetGuard ou em um snmpwalk.")
        examples = self._section_card(parent, "OIDs Uteis", "Referencias diretas para system, interfaces e bridge/STP.")
        notes = self._section_card(parent, "Observacoes", "As respostas SNMP refletem o estado vivo do simulador.")

        status.grid(row=0, column=0, sticky="nsew", padx=(14, 8), pady=(14, 8))
        config.grid(row=0, column=1, sticky="nsew", padx=(8, 14), pady=(14, 8))
        examples.grid(row=1, column=0, sticky="nsew", padx=(14, 8), pady=(8, 14))
        notes.grid(row=1, column=1, sticky="nsew", padx=(8, 14), pady=(8, 14))

        for key, title in (("snmp_service", "Servico"), ("snmp_bind", "Bind"), ("snmp_community", "Community"), ("snmp_queries_detail", "Queries")):
            panel = self._frame(status, fg_color="#0f172a" if self.using_ctk else None, corner_radius=14 if self.using_ctk else None)
            panel.pack(fill="x", padx=16, pady=6)
            self._label(panel, title, font=("Segoe UI", 11), text_color="#93c5fd" if self.using_ctk else None).pack(anchor="w", padx=12, pady=(10, 2))
            value = self._label(panel, "--", font=("Segoe UI Semibold", 15), text_color="#f8fafc" if self.using_ctk else None, wraplength=400 if self.using_ctk else None, justify="left")
            value.pack(anchor="w", padx=12, pady=(0, 10))
            self.protocol_status_labels[key] = value

        self.snmp_info_text = self._textbox(examples, height=360)
        self.snmp_info_text.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self._set_textbox(
            self.snmp_info_text,
            "OIDs recomendados\n"
            "1.3.6.1.2.1.1.1.0   sysDescr\n"
            "1.3.6.1.2.1.1.5.0   sysName\n"
            "1.3.6.1.2.1.2.1.0   ifNumber\n"
            "1.3.6.1.2.1.2.2.1.8.1   ifOperStatus.1\n"
            "1.3.6.1.2.1.2.2.1.10.1  ifInOctets.1\n"
            "1.3.6.1.2.1.31.1.1.1.6.1  ifHCInOctets.1\n"
            "1.3.6.1.2.1.17.2.4.0  dot1dStpTopChanges\n",
        )

        config_text = self._textbox(config, height=180)
        config_text.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self._set_textbox(
            config_text,
            "Capacidades\n"
            "- GET\n"
            "- GETNEXT\n"
            "- GETBULK\n"
            "- SET parcial para sysName, sysContact, sysLocation e ifAdminStatus\n\n"
            "Os contadores mudam conforme flap, storm, burst, loop e discards.",
        )

        notes_text = self._textbox(notes, height=180)
        notes_text.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self._set_textbox(
            notes_text,
            "Importante\n"
            "- O agente tenta bindar no IP de gerencia configurado.\n"
            "- Se o IP nao existir localmente ou a porta 161 estiver ocupada, a GUI vai exibir o erro de bind.\n"
            "- Mesmo sem abrir o NetGuard, voce pode validar rapidamente com snmpwalk/snmpget externos.",
        )

    def _build_syslog_tab(self, parent) -> None:
        if self.using_ctk:
            parent.grid_columnconfigure(0, weight=1)
            parent.grid_columnconfigure(1, weight=1)
            parent.grid_rowconfigure(1, weight=1)
        else:
            parent.columnconfigure(0, weight=1)
            parent.columnconfigure(1, weight=1)
            parent.rowconfigure(1, weight=1)

        status = self._section_card(parent, "Saida de Syslog", "Veja rapidamente para onde os eventos estao sendo enviados.")
        samples = self._section_card(parent, "Mensagens Esperadas", "Exemplos no estilo de switch real para correlacao com o NetGuard.")
        operations = self._section_card(parent, "Quando Cada Evento Aparece", "Mapa simples entre a acao na GUI e o syslog esperado.")
        notes = self._section_card(parent, "Lembretes", "Resumo de uso e dependencias de bind.")

        status.grid(row=0, column=0, sticky="nsew", padx=(14, 8), pady=(14, 8))
        samples.grid(row=0, column=1, sticky="nsew", padx=(8, 14), pady=(14, 8))
        operations.grid(row=1, column=0, sticky="nsew", padx=(14, 8), pady=(8, 14))
        notes.grid(row=1, column=1, sticky="nsew", padx=(8, 14), pady=(8, 14))

        for key, title in (("syslog_service", "Servico"), ("syslog_target", "Destino"), ("trap_target", "Trap destino"), ("syslog_count", "Mensagens enviadas")):
            panel = self._frame(status, fg_color="#0f172a" if self.using_ctk else None, corner_radius=14 if self.using_ctk else None)
            panel.pack(fill="x", padx=16, pady=6)
            self._label(panel, title, font=("Segoe UI", 11), text_color="#93c5fd" if self.using_ctk else None).pack(anchor="w", padx=12, pady=(10, 2))
            value = self._label(panel, "--", font=("Segoe UI Semibold", 15), text_color="#f8fafc" if self.using_ctk else None, wraplength=400 if self.using_ctk else None, justify="left")
            value.pack(anchor="w", padx=12, pady=(0, 10))
            self.protocol_status_labels[key] = value

        self.syslog_info_text = self._textbox(samples, height=240)
        self.syslog_info_text.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self._set_textbox(
            self.syslog_info_text,
            "%LINK-3-UPDOWN\n"
            "%LINEPROTO-5-UPDOWN\n"
            "%SPANTREE-2-LOOPGUARD_BLOCK\n"
            "%SPANTREE-5-TOPOTRAP\n"
            "%STORMCTRL-3-FIRE\n"
            "%SW_MATM-4-MACFLAP_NOTIF\n"
            "%PM-4-ERR_DISABLE\n",
        )

        ops_text = self._textbox(operations, height=240)
        ops_text.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self._set_textbox(
            ops_text,
            "Acao -> sinal esperado\n"
            "- Admin Down: LINK e LINEPROTO down\n"
            "- Admin Up: LINK e LINEPROTO up\n"
            "- Storm: mensagens de storm control\n"
            "- Loop protegido: loopguard block + topotrap\n"
            "- Loop sem bloqueio: topotrap + MAC flapping + storm\n"
            "- Err-disable: mensagem de err-disable\n",
        )

        note_text = self._textbox(notes, height=240)
        note_text.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self._set_textbox(
            note_text,
            "O simulador envia syslog RFC 3164 por UDP.\n"
            "Os traps SNMP acompanham varios eventos relevantes para correlacao.\n"
            "Se o bind falhar, o problema costuma ser IP local ausente ou porta ja usada.",
        )

    def _build_logs_tab(self, parent) -> None:
        if self.using_ctk:
            parent.grid_columnconfigure(0, weight=2)
            parent.grid_columnconfigure(1, weight=1)
            parent.grid_rowconfigure(0, weight=1)
        else:
            parent.columnconfigure(0, weight=2)
            parent.columnconfigure(1, weight=1)
            parent.rowconfigure(0, weight=1)

        live = self._section_card(parent, "Eventos ao Vivo", "Feed central para acompanhar o que foi disparado e como o equipamento reagiu.")
        hints = self._section_card(parent, "Leitura Rapida", "Como interpretar os eventos para cada classe de teste.")
        live.grid(row=0, column=0, sticky="nsew", padx=(14, 8), pady=14)
        hints.grid(row=0, column=1, sticky="nsew", padx=(8, 14), pady=14)

        self.log_text = self._textbox(live)
        self.log_text.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        hints_text = self._textbox(hints, height=420)
        hints_text.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self._set_textbox(
            hints_text,
            "Interpretacao sugerida\n"
            "- Muitos increments de erro/discards: degradacao ou loop sem bloqueio.\n"
            "- LINK up/down repetido: flap.\n"
            "- SPANTREE com block: contencao automatica atuou.\n"
            "- MAC flapping + storm + octets disparando: loop aberto.\n"
            "- Err-disable: porta isolada logicamente.\n",
        )

    def _build_config_tab(self, parent) -> None:
        if self.using_ctk:
            parent.grid_columnconfigure(0, weight=2)
            parent.grid_columnconfigure(1, weight=1)
            parent.grid_rowconfigure(0, weight=1)
        else:
            parent.columnconfigure(0, weight=2)
            parent.columnconfigure(1, weight=1)
            parent.rowconfigure(0, weight=1)

        form_card = self._section_card(parent, "Configuracao do Equipamento", "Edite identidade, bind de gerenciamento, community e destinos.")
        note_card = self._section_card(parent, "Boas Praticas", "Evite duvidas operacionais durante os testes.")
        form_card.grid(row=0, column=0, sticky="nsew", padx=(14, 8), pady=14)
        note_card.grid(row=0, column=1, sticky="nsew", padx=(8, 14), pady=14)

        form = self._frame(form_card, fg_color="transparent" if self.using_ctk else None)
        form.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        fields = [
            ("hostname", "Hostname"),
            ("description", "Descricao"),
            ("contact", "Contato"),
            ("location", "Local"),
            ("management_ip", "IP de gerencia"),
            ("management_prefix", "Prefixo"),
            ("gateway", "Gateway"),
            ("community", "Community SNMP"),
            ("snmp_port", "Porta SNMP"),
            ("trap_host", "Trap host"),
            ("trap_port", "Trap port"),
            ("syslog_host", "Syslog host"),
            ("syslog_port", "Syslog port"),
        ]
        for row, (key, label_text) in enumerate(fields):
            form.grid_columnconfigure(1, weight=1)
            self._label(form, label_text, font=("Segoe UI", 12), text_color="#93c5fd" if self.using_ctk else None).grid(row=row, column=0, sticky="w", padx=8, pady=8)
            var = tk.StringVar()
            self.config_entries[key] = var
            self._entry(form, var, width=320).grid(row=row, column=1, sticky="ew", padx=8, pady=8)

        buttons = self._frame(form_card, fg_color="transparent" if self.using_ctk else None)
        buttons.pack(fill="x", padx=16, pady=(0, 16))
        self._button(buttons, "Validar IP Local", self.controller.validate_management_ip, fg_color="#0f766e" if self.using_ctk else None).pack(side="left", padx=6)
        self._button(buttons, "Salvar Configuracao", self.controller.save_configuration, fg_color="#374151" if self.using_ctk else None).pack(side="left", padx=6)
        self._button(buttons, "Aplicar e Reiniciar Servicos", self.controller.apply_configuration, fg_color="#1d4ed8" if self.using_ctk else None).pack(side="left", padx=6)

        notes = self._textbox(note_card)
        notes.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self._set_textbox(
            notes,
            "Regras importantes\n"
            "- O simulador nao cria placa de rede nem IP virtual.\n"
            "- O IP de gerencia precisa existir localmente no Windows para bindar servicos.\n"
            "- Se a porta 161 ja estiver ocupada, o bind SNMP falhara mesmo com o IP correto.\n"
            "- Salvar persiste em JSON; aplicar tambem reinicia SNMP, syslog e traps.\n\n"
            "Fluxo recomendado\n"
            "1. Ajuste IP, portas e destinos.\n"
            "2. Valide o IP local.\n"
            "3. Aplique a configuracao.\n"
            "4. Volte ao Dashboard para rodar os cenarios.\n",
        )

    def _on_tree_select(self, _event=None) -> None:
        if not self.interface_tree:
            return
        selection = self.interface_tree.selection()
        if not selection:
            return
        item_id = selection[0]
        name = self.interface_index_names.get(int(item_id))
        if name:
            self.interface_vars["selected_if"].set(name)

    def get_selected_interface(self) -> int:
        return self._port_name_to_index(self.interface_vars["selected_if"].get())

    def get_flap_interval(self) -> int:
        return int(self.interface_vars["flap_interval"].get())

    def get_loop_ports(self) -> tuple[int, int]:
        return (
            self._port_name_to_index(self.interface_vars["loop_a"].get()),
            self._port_name_to_index(self.interface_vars["loop_b"].get()),
        )

    def get_stp_modes(self) -> dict[str, bool]:
        return {
            "enabled": bool(self.interface_vars["stp_enabled"].get()),
            "loop_guard_enabled": bool(self.interface_vars["loop_guard_enabled"].get()),
            "auto_block_on_loop": bool(self.interface_vars["auto_block_on_loop"].get()),
        }

    def load_config_values(self, config) -> None:
        values = {
            "hostname": config.device.hostname,
            "description": config.device.description,
            "contact": config.device.contact,
            "location": config.device.location,
            "management_ip": config.device.management_ip,
            "management_prefix": str(config.device.management_prefix),
            "gateway": config.device.gateway,
            "community": config.snmp.community,
            "snmp_port": str(config.snmp.bind_port),
            "trap_host": config.snmp.trap_host,
            "trap_port": str(config.snmp.trap_port),
            "syslog_host": config.syslog.remote_host,
            "syslog_port": str(config.syslog.remote_port),
        }
        for key, value in values.items():
            if key in self.config_entries:
                self.config_entries[key].set(value)
        if "stp_enabled" in self.interface_vars:
            self.interface_vars["stp_enabled"].set(config.stp.enabled)
            self.interface_vars["loop_guard_enabled"].set(config.stp.loop_guard_enabled)
            self.interface_vars["auto_block_on_loop"].set(config.stp.auto_block_on_loop)
        self._update_port_selectors(config.interfaces)

    def collect_config_values(self, config):
        updated = copy.deepcopy(config)
        updated.device.hostname = self.config_entries["hostname"].get().strip()
        updated.device.description = self.config_entries["description"].get().strip()
        updated.device.contact = self.config_entries["contact"].get().strip()
        updated.device.location = self.config_entries["location"].get().strip()
        updated.device.management_ip = validate_ipv4(self.config_entries["management_ip"].get().strip())
        updated.device.management_prefix = validate_prefix(self.config_entries["management_prefix"].get().strip())
        updated.device.gateway = validate_ipv4(self.config_entries["gateway"].get().strip())
        updated.snmp.community = self.config_entries["community"].get().strip()
        updated.snmp.bind_port = int(self.config_entries["snmp_port"].get().strip())
        updated.snmp.trap_host = validate_ipv4(self.config_entries["trap_host"].get().strip())
        updated.snmp.trap_port = int(self.config_entries["trap_port"].get().strip())
        updated.syslog.remote_host = validate_ipv4(self.config_entries["syslog_host"].get().strip())
        updated.syslog.remote_port = int(self.config_entries["syslog_port"].get().strip())
        modes = self.get_stp_modes()
        updated.stp.enabled = modes["enabled"]
        updated.stp.loop_guard_enabled = modes["loop_guard_enabled"]
        updated.stp.auto_block_on_loop = modes["auto_block_on_loop"]
        return updated

    def show_info(self, title: str, message: str) -> None:
        messagebox.showinfo(title, message, parent=self.root)

    def show_error(self, title: str, message: str) -> None:
        messagebox.showerror(title, message, parent=self.root)

    def append_logs(self, events: list[dict[str, str]]) -> None:
        lines = [f"[{event['timestamp']}] {event['level']:<7} {event['message']}" for event in events]
        self._append_textbox_lines(self.log_text, self._log_history, lines, limit=800)
        self._append_textbox_lines(self.dashboard_events_text, self._dashboard_history, lines[-80:], limit=80)

    def update_snapshot(self, snapshot: dict) -> None:
        stats = snapshot["stats"]
        config = snapshot["config"]

        self.metrics_labels["snmp_status"].configure(text="Online" if "ouvindo" in stats["snmp_status"].lower() else "Atencao")
        self.metrics_labels["management_ip"].configure(text=stats["management_ip"])
        self.metrics_labels["interfaces"].configure(text=f"{stats['interfaces_up']} up / {stats['interfaces_down']} down")
        self.metrics_labels["loops_active"].configure(text=str(stats["loops_active"]))
        self.metrics_labels["total_errors"].configure(text=str(stats["total_errors"]))
        self.metrics_labels["tc_count"].configure(text=str(stats["tc_count"]))

        self.detail_labels["hostname"].configure(text=stats["hostname"])
        self.detail_labels["gateway"].configure(text=stats["gateway"])
        self.detail_labels["uptime"].configure(text=f"{stats['uptime']}s")
        self.detail_labels["snmp_queries"].configure(text=str(stats["snmp_queries"]))
        self.detail_labels["traps_sent"].configure(text=str(stats["traps_sent"]))
        self.detail_labels["syslog_sent"].configure(text=str(stats["syslog_sent"]))
        self.detail_labels["root_bridge_id"].configure(text=stats["root_bridge_id"])
        self.detail_labels["stp_mode"].configure(text=f"STP {'ON' if stats['stp_enabled'] else 'OFF'} | Loop Guard {'ON' if stats['loop_guard_enabled'] else 'OFF'} | Auto {'ON' if stats['auto_block_on_loop'] else 'OFF'}")

        self.detail_labels["stp_state"].configure(text="Protecao ativa" if stats["stp_enabled"] else "STP desabilitado")
        self.detail_labels["stp_root"].configure(text=stats["root_bridge_id"])
        self.detail_labels["stp_tc"].configure(text=str(stats["tc_count"]))
        self.detail_labels["stp_loops"].configure(text=str(stats["loops_active"]))

        self.protocol_status_labels["snmp_service"].configure(text=stats["snmp_status"])
        self.protocol_status_labels["snmp_bind"].configure(text=f"{config.device.management_ip}:{config.snmp.bind_port}")
        self.protocol_status_labels["snmp_community"].configure(text=config.snmp.community)
        self.protocol_status_labels["snmp_queries_detail"].configure(text=str(stats["snmp_queries"]))
        self.protocol_status_labels["syslog_service"].configure(text="Ativo" if config.syslog.enabled else "Desabilitado")
        self.protocol_status_labels["syslog_target"].configure(text=f"{config.syslog.remote_host}:{config.syslog.remote_port}")
        self.protocol_status_labels["trap_target"].configure(text=f"{config.snmp.trap_host}:{config.snmp.trap_port}")
        self.protocol_status_labels["syslog_count"].configure(text=str(stats["syslog_sent"]))

        bind_warning = (
            "IP local detectado. Bind e ping podem funcionar normalmente."
            if ip_exists_locally(config.device.management_ip)
            else "IP de gerencia nao foi detectado localmente. Bind e ping dependem desse IP existir no Windows."
        )
        self.summary_labels["bind_warning"].configure(text=bind_warning)

        self._update_interface_tree(snapshot["interfaces"])
        self._update_selected_interface_summary(snapshot["interfaces"])

    def _update_interface_tree(self, interfaces) -> None:
        for interface in interfaces:
            values = (
                interface.name,
                "up" if interface.admin_up else "down",
                "up" if interface.oper_up else "down",
                interface.mode,
                interface.vlan_access,
                f"{interface.speed_mbps}M",
                interface.duplex,
                interface.stp_state,
                interface.stp_role,
                interface.in_octets,
                interface.out_octets,
                interface.in_errors + interface.out_errors,
                interface.in_discards + interface.out_discards,
                interface.local_loop_peer or "-",
                interface.description,
            )
            item_id = str(interface.if_index)
            self.interface_index_names[interface.if_index] = interface.name
            if item_id not in self.tree_items:
                self.interface_tree.insert("", "end", iid=item_id, values=values)
                self.tree_items[item_id] = values
            elif self.tree_items[item_id] != values:
                self.interface_tree.item(item_id, values=values)
                self.tree_items[item_id] = values

    def _update_selected_interface_summary(self, interfaces) -> None:
        if not interfaces:
            return
        wanted_name = self.interface_vars["selected_if"].get()
        selected = next((interface for interface in interfaces if interface.name == wanted_name), interfaces[0])
        self.detail_labels["selected_name"].configure(text=selected.name)
        self.detail_labels["selected_link"].configure(text=f"admin {'up' if selected.admin_up else 'down'} | oper {'up' if selected.oper_up else 'down'} | err-disable {'on' if selected.errdisable else 'off'}")
        self.detail_labels["selected_mode"].configure(text=f"{selected.mode} | {selected.speed_mbps}M | {selected.duplex}")
        self.detail_labels["selected_vlan"].configure(text=str(selected.vlan_access))
        self.detail_labels["selected_stp"].configure(text=f"{selected.stp_state} | {selected.stp_role}")
        self.detail_labels["selected_counters"].configure(text=f"in {selected.in_octets} / out {selected.out_octets} / err {selected.in_errors + selected.out_errors} / disc {selected.in_discards + selected.out_discards}")

    def _update_port_selectors(self, interfaces) -> None:
        values = [interface.name for interface in interfaces] or ["Gi0/1"]
        for widget_name in ("interface_selector", "loop_a_selector", "loop_b_selector"):
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            if self.using_ctk:
                widget.configure(values=values)
            else:
                widget["values"] = values
        if self.interface_vars["selected_if"].get() not in values:
            self.interface_vars["selected_if"].set(values[0])
        if self.interface_vars["loop_a"].get() not in values:
            self.interface_vars["loop_a"].set(values[0])
        if self.interface_vars["loop_b"].get() not in values:
            self.interface_vars["loop_b"].set(values[1] if len(values) > 1 else values[0])
        self.interface_index_names = {interface.if_index: interface.name for interface in interfaces}

    def _port_name_to_index(self, value: str) -> int:
        if value.startswith("Gi0/"):
            return int(value.split("/")[-1])
        return int(value)

    def management_ip_exists(self) -> bool:
        return ip_exists_locally(self.config_entries["management_ip"].get().strip())

    def local_ips_text(self) -> str:
        return ", ".join(iter_local_ipv4_addresses()) or "nenhum IPv4 local detectado"
