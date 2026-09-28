from __future__ import annotations

import copy

from .config import load_config, save_config
from .gui import SimulatorGUI
from .logging_utils import setup_logging
from .simulation import SwitchSimulator


class NetGuardSimulatorApp:
    def __init__(self) -> None:
        self.logger = setup_logging()
        self.config = load_config()
        self.simulator = SwitchSimulator(copy.deepcopy(self.config), self.logger)
        self.gui = SimulatorGUI(self)
        self.root = self.gui.build()
        self.gui.load_config_values(self.config)
        self.simulator.start()

    def run(self) -> None:
        self._refresh()
        self.root.mainloop()

    def on_close(self) -> None:
        self.simulator.stop()
        self.root.destroy()

    def _refresh(self) -> None:
        snapshot = self.simulator.build_snapshot()
        self.gui.update_snapshot(snapshot)
        self.gui.append_logs(self.simulator.dequeue_events())
        self.root.after(self.config.simulation.ui_refresh_ms, self._refresh)

    def set_selected_admin(self, admin_up: bool) -> None:
        try:
            self.simulator.set_interface_admin(self.gui.get_selected_interface(), admin_up)
        except Exception as exc:
            self.gui.show_error("Interface", str(exc))

    def trigger_selected_error_burst(self) -> None:
        try:
            self.simulator.trigger_error_burst(self.gui.get_selected_interface())
        except Exception as exc:
            self.gui.show_error("Burst de Erros", str(exc))

    def trigger_selected_discards(self) -> None:
        try:
            self.simulator.trigger_discards(self.gui.get_selected_interface())
        except Exception as exc:
            self.gui.show_error("Discards", str(exc))

    def toggle_selected_storm(self) -> None:
        try:
            if_index = self.gui.get_selected_interface()
            snapshot = self.simulator.build_snapshot()
            target = next(item for item in snapshot["interfaces"] if item.if_index == if_index)
            self.simulator.trigger_storm(if_index, not target.storm_active)
        except Exception as exc:
            self.gui.show_error("Storm", str(exc))

    def toggle_selected_errdisable(self) -> None:
        try:
            self.simulator.toggle_errdisable(self.gui.get_selected_interface())
        except Exception as exc:
            self.gui.show_error("Err-Disable", str(exc))

    def toggle_selected_flap(self) -> None:
        try:
            if_index = self.gui.get_selected_interface()
            interval = self.gui.get_flap_interval()
            snapshot = self.simulator.build_snapshot()
            target = next(item for item in snapshot["interfaces"] if item.if_index == if_index)
            self.simulator.trigger_flap(if_index, not target.flap_enabled, interval)
        except Exception as exc:
            self.gui.show_error("Flap", str(exc))

    def simulate_protected_loop(self) -> None:
        self._simulate_loop(protected=True)

    def simulate_unprotected_loop(self) -> None:
        self._simulate_loop(protected=False)

    def _simulate_loop(self, protected: bool) -> None:
        try:
            first, second = self.gui.get_loop_ports()
            if first == second:
                raise ValueError("Escolha duas portas diferentes para o loop.")
            self.simulator.set_loop_between(first, second, protected)
        except Exception as exc:
            self.gui.show_error("Loop", str(exc))

    def clear_loops(self) -> None:
        self.simulator.clear_loops()

    def trigger_tcn(self) -> None:
        self.simulator.trigger_tcn()

    def reelect_root(self) -> None:
        self.simulator.reelect_root()

    def apply_stp_modes(self) -> None:
        updated = copy.deepcopy(self.config)
        modes = self.gui.get_stp_modes()
        updated.stp.enabled = modes["enabled"]
        updated.stp.loop_guard_enabled = modes["loop_guard_enabled"]
        updated.stp.auto_block_on_loop = modes["auto_block_on_loop"]
        self.config = updated
        self.simulator.update_config(updated)
        save_config(updated)
        self.gui.show_info("STP", "Modos STP atualizados.")

    def validate_management_ip(self) -> None:
        try:
            exists = self.gui.management_ip_exists()
            text = (
                "IP encontrado localmente. O bind de serviços e o ping podem funcionar."
                if exists
                else "IP não encontrado localmente. O simulador não cria interface real; bind e ping dependem desse IP existir no Windows."
            )
            text += f"\n\nIPs locais detectados: {self.gui.local_ips_text()}"
            self.gui.show_info("Validação de IP", text)
        except Exception as exc:
            self.gui.show_error("Validação de IP", str(exc))

    def save_configuration(self) -> None:
        try:
            updated = self.gui.collect_config_values(self.config)
            save_config(updated)
            self.config = updated
            self.gui.show_info("Configuração", "Configuração salva com sucesso.")
        except Exception as exc:
            self.gui.show_error("Configuração", str(exc))

    def apply_configuration(self) -> None:
        try:
            updated = self.gui.collect_config_values(self.config)
            save_config(updated)
            self.config = updated
            status = self.simulator.update_config(updated)
            self.gui.load_config_values(updated)
            self.gui.show_info(
                "Aplicar Configuração",
                f"SNMP: {status['snmp']}\nSyslog: {status['syslog']}\nTraps: {status['traps']}\n\n"
                "Lembrete: o ping e o bind dependem de o IP de gerenciamento existir de fato no Windows.",
            )
        except Exception as exc:
            self.gui.show_error("Aplicar Configuração", str(exc))
