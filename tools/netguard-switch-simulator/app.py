from __future__ import annotations

import sys
import traceback
from pathlib import Path


def _write_boot_error(exc: BaseException) -> Path:
    base_dir = Path(__file__).resolve().parent
    log_dir = base_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    error_file = log_dir / "startup_error.log"
    with error_file.open("a", encoding="utf-8") as handle:
        handle.write("\n=== NetGuard Switch Simulator startup failure ===\n")
        handle.write("".join(traceback.format_exception(exc)))
    return error_file


def main() -> int:
    try:
        from simulator.app_controller import NetGuardSimulatorApp

        app = NetGuardSimulatorApp()
        app.run()
        return 0
    except Exception as exc:  # pragma: no cover - startup safety
        error_file = _write_boot_error(exc)
        print(
            "NetGuard Switch Simulator falhou ao iniciar. "
            f"Veja o log em: {error_file}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
