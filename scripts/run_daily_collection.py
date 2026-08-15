"""Daily collection orchestrator — runs collectors then stats as subprocesses."""

import subprocess
import sys
from datetime import datetime
from pathlib import Path

# Resolve project root so subprocess calls use absolute paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent

COLLECTORS = [
    ("URLhaus", PROJECT_ROOT / "collectors" / "urlhaus.py"),
    ("AbuseIPDB", PROJECT_ROOT / "collectors" / "abuseipdb.py"),
]

STATS_SCRIPT = PROJECT_ROOT / "analytics" / "stats.py"


def _run_script(label: str, script_path: Path) -> int:
    """Run a Python script as a subprocess and return its exit code.

    Never raises — logs the error and returns the exit code (or -1 on exception).
    """
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n[{ts}] >> Lancement de {label} ({script_path.name})...")

    try:
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(PROJECT_ROOT),
        )
        code = result.returncode
    except Exception as exc:
        print(f"[{ts}] ERREUR {label} - exception inattendue : {exc}")
        return -1

    ts_end = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if code == 0:
        print(f"[{ts_end}] OK {label} termine avec succes (code retour {code}).")
    else:
        print(f"[{ts_end}] ECHEC {label} a echoue (code retour {code}). On continue.")

    return code


def main() -> None:
    """Run all collectors, then stats. Never crashes on a single failure."""
    start = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("=" * 60)
    print(f"=== Collecte quotidienne - demarrage {start} ===")
    print("=" * 60)

    results = {}
    for label, path in COLLECTORS:
        results[label] = _run_script(label, path)

    # Analytics
    results["Stats"] = _run_script("Stats", STATS_SCRIPT)

    # Final summary
    ts_final = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("\n" + "=" * 60)
    print(f"=== Resume - {ts_final} ===")
    for name, code in results.items():
        status = "OK" if code == 0 else f"ECHEC (code {code})"
        print(f"  {name:12s} : {status}")
    print("=" * 60)


if __name__ == "__main__":
    main()