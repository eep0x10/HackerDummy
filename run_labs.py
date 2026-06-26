#!/usr/bin/env python3
"""
run_labs.py — HackerDummy lab runner (cross-platform: Windows + Linux + macOS).

Boots every runnable lab under ./labs (each `app.py`, or `serve.sh` for the PHP
lab), prints a live table of LAB / folder / status / port, and tears everything
down on CTRL+C. Each port is a different lab.

Process control and port detection are cross-platform:
  - spawn:  POSIX -> start_new_session; Windows -> CREATE_NEW_PROCESS_GROUP
  - alive:  Popen.poll()  (no /proc dependency)
  - port:   parse the lab's startup log for its URL, confirm with a TCP probe
  - kill:   POSIX -> killpg(SIGTERM/SIGKILL); Windows -> taskkill /F /T

Mobile labs (labs/mobile/*) are STATIC artifacts (no server) and are not booted
here — analyze them with jadx/apktool. See labs/mobile/MOBILE.md.

    python run_labs.py            # boot all, CTRL+C to stop
    python run_labs.py --timeout 8
"""
import os
import re
import sys
import time
import socket
import signal
import argparse
import subprocess
from pathlib import Path
from datetime import datetime

ROOT_DIR = Path(__file__).resolve().parent
LABS_DIR = ROOT_DIR / "labs"
LOG_DIR = ROOT_DIR / ".lab_logs"
PYTHON_BIN = sys.executable
IS_WIN = os.name == "nt"

# labs whose entrypoint isn't app.py
LAB_COMMAND_OVERRIDES = {
    "11-legacyportal": ["bash", "serve.sh"],
}

processes = []
shutdown_requested = False
USE_COLOR = True

COLS = [("LAB", 5), ("Pasta", 30), ("Status", 8), ("Port", 24)]

_URL_RE = re.compile(
    r"(?:http://)?(?:127\.0\.0\.1|0\.0\.0\.0|localhost|\[[^\]]+\]):(\d{2,5})")


class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"
    BLUE = "\033[34m"; CYAN = "\033[36m"; WHITE = "\033[37m"


def paint(text, color, enabled=True):
    return text if not enabled else f"{color}{text}{C.RESET}"


def pad(text, width):
    text = str(text)
    return (text[: width - 1] + "…") if len(text) > width else text.ljust(width)


def banner(use_color):
    print(paint("╔" + "═" * 74 + "╗", C.CYAN, use_color))
    print(paint("║", C.CYAN, use_color)
          + paint(f"{'HackerDummy Lab Runner':^74}", C.BOLD + C.GREEN, use_color)
          + paint("║", C.CYAN, use_color))
    print(paint("║", C.CYAN, use_color)
          + paint(f"{'Cada porta representa um LAB diferente':^74}", C.YELLOW, use_color)
          + paint("║", C.CYAN, use_color))
    print(paint("╚" + "═" * 74 + "╝", C.CYAN, use_color))
    print()


def _border(left, mid, right, use_color):
    print(paint(left + mid.join("─" * (w + 2) for _, w in COLS) + right, C.BLUE, use_color))


def table_header(use_color):
    _border("┌", "┬", "┐", use_color)
    row = paint("│", C.BLUE, use_color)
    for title, width in COLS:
        row += " " + paint(pad(title, width), C.BOLD + C.WHITE, use_color) + " " + paint("│", C.BLUE, use_color)
    print(row)
    _border("├", "┼", "┤", use_color)


def table_row(lab, folder, status, port, use_color):
    status_color = C.BOLD + C.GREEN if status == "UP" else C.BOLD + C.RED
    port_color = C.CYAN if port.startswith("127.0.0.1:") else C.DIM + C.WHITE
    values = [(str(lab), C.WHITE), (folder, C.WHITE), (status, status_color), (port, port_color)]
    row = paint("│", C.BLUE, use_color)
    for (_, width), (value, vcolor) in zip(COLS, values):
        row += " " + paint(pad(value, width), vcolor, use_color) + " " + paint("│", C.BLUE, use_color)
    print(row)


def resolve_lab_command(folder):
    if folder.name in LAB_COMMAND_OVERRIDES:
        command = LAB_COMMAND_OVERRIDES[folder.name]
        return command if (folder / command[-1]).is_file() else None
    if (folder / "app.py").is_file():
        return [PYTHON_BIN, "app.py"]
    if (folder / "serve.sh").is_file():
        return ["bash", "serve.sh"]
    return None


def command_to_string(command):
    return "python app.py" if command[0] == PYTHON_BIN else " ".join(command)


def lab_sort_key(folder):
    m = re.match(r"^(\d+)-", folder.name)
    return int(m.group(1)) if m else 9999


def discover_labs():
    if not LABS_DIR.exists():
        print(paint(f"[!] Diretório não encontrado: {LABS_DIR}", C.RED, USE_COLOR))
        sys.exit(1)
    found = [f for f in LABS_DIR.iterdir() if f.is_dir() and resolve_lab_command(f)]
    return sorted(found, key=lab_sort_key)


def _popen(command, cwd, log):
    kwargs = dict(cwd=str(cwd), stdout=log, stderr=log, stdin=subprocess.DEVNULL,
                  env={**os.environ, "PYTHONUNBUFFERED": "1"})
    if IS_WIN:
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen(command, **kwargs)


def _tcp_open(port, host="127.0.0.1", timeout=0.3):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def port_from_log(log_file, offset=0):
    try:
        size = log_file.stat().st_size
        if offset > size:
            offset = 0
        with open(log_file, "rb") as f:
            f.seek(max(size - 16000, offset))
            content = f.read().decode(errors="ignore")
    except FileNotFoundError:
        return None
    matches = _URL_RE.findall(content)
    return f"127.0.0.1:{matches[-1]}" if matches else None


def wait_for_port(proc, log_file, offset, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return None
        port = port_from_log(log_file, offset)
        if port and _tcp_open(port.split(":")[1]):
            return port
        time.sleep(0.2)
    return port_from_log(log_file, offset)


def stop_proc(lab):
    proc = lab["process"]
    if proc.poll() is not None:
        return
    try:
        if IS_WIN:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            for _ in range(20):
                if proc.poll() is not None:
                    break
                time.sleep(0.1)
            if proc.poll() is None:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, OSError):
        pass


def start_labs(use_color, startup_timeout):
    LOG_DIR.mkdir(exist_ok=True)
    lab_dirs = discover_labs()
    if not lab_dirs:
        print(paint("[!] Nenhum lab executável encontrado em ./labs", C.RED, use_color))
        sys.exit(1)
    table_header(use_color)
    for index, folder in enumerate(lab_dirs, start=1):
        command = resolve_lab_command(folder)
        log_file = LOG_DIR / f"{folder.name}.log"
        offset = log_file.stat().st_size if log_file.exists() else 0
        try:
            with open(log_file, "ab", buffering=0) as log:
                log.write(f"\n\n===== START {datetime.now().isoformat()} =====\n".encode())
                log.write(f"COMMAND: {command_to_string(command)}\n".encode())
                proc = _popen(command, folder, log)
            lab = {"index": index, "folder": folder, "process": proc, "log_file": log_file}
            processes.append(lab)
            port = wait_for_port(proc, log_file, offset, startup_timeout)
            alive = proc.poll() is None
            table_row(index, folder.name, "UP" if alive else "DOWN", port or "N/A", use_color)
        except Exception as exc:
            with open(log_file, "ab", buffering=0) as log:
                log.write(f"ERROR: {exc}\n".encode())
            table_row(index, folder.name, "DOWN", "N/A", use_color)
    _border("└", "┴", "┘", use_color)


def stop_labs(use_color):
    global shutdown_requested
    if shutdown_requested:
        return
    shutdown_requested = True
    print("\n" + paint("[!] Derrubando todos os labs...", C.BOLD + C.YELLOW, use_color) + "\n")
    for lab in processes:
        if lab["process"].poll() is None:
            print(paint("[STOP]", C.YELLOW, use_color), f"LAB {lab['index']} - {lab['folder'].name}")
            stop_proc(lab)
    print("\n" + paint("[+] Todos os labs foram finalizados.", C.BOLD + C.GREEN, use_color))
    print(paint(f"[+] Logs: {LOG_DIR}", C.DIM + C.WHITE, use_color))


def handle_shutdown(signum, frame):
    stop_labs(USE_COLOR)
    sys.exit(0)


def main():
    global USE_COLOR
    ap = argparse.ArgumentParser(description="Sobe todos os labs HTTP do HackerDummy; CTRL+C derruba tudo.")
    ap.add_argument("--no-color", action="store_true", help="Desativa cores ANSI.")
    ap.add_argument("--timeout", type=float, default=5.0, help="Timeout (s) p/ detectar a porta. Padrão: 5.")
    args = ap.parse_args()
    USE_COLOR = not args.no_color and sys.stdout.isatty()
    signal.signal(signal.SIGINT, handle_shutdown)
    try:
        signal.signal(signal.SIGTERM, handle_shutdown)
    except (ValueError, AttributeError):
        pass
    print("\033c", end="")
    banner(USE_COLOR)
    start_labs(USE_COLOR, args.timeout)
    print("\n" + paint("[+] Todos os labs disponíveis foram processados.", C.BOLD + C.GREEN, USE_COLOR))
    print(paint("[+] Pressione CTRL+C para derrubar tudo.", C.BOLD + C.YELLOW, USE_COLOR))
    print(paint(f"[+] Logs: {LOG_DIR}\n", C.DIM + C.WHITE, USE_COLOR))
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_labs(USE_COLOR)


if __name__ == "__main__":
    main()
