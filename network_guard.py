from __future__ import annotations

import csv
import html
import json
import locale
import os
import platform
import queue
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from collections import Counter, deque
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from tkinter import BOTH, END, LEFT, RIGHT, X, Y, BooleanVar, StringVar, Tk, Toplevel, filedialog, messagebox
from tkinter import ttk
from typing import Any, Deque, Dict, Iterable, Optional, Tuple

APP_NAME = "Network Guard"
APP_VERSION = "1.0.1"
BASE_DIR = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
REPORT_DIR = BASE_DIR / "reports"
CONFIG_PATH = BASE_DIR / "config.json"
EVENT_LOG = DATA_DIR / "events.jsonl"
SAMPLE_LOG = DATA_DIR / "samples.csv"

DEFAULT_CONFIG = {
    "fast_interval_sec": 5,
    "protocol_interval_sec": 15,
    "topology_interval_sec": 60,
    "wifi_interval_sec": 30,
    "ping_timeout_ms": 1200,
    "socket_timeout_sec": 2.0,
    "public_ping_targets": ["1.1.1.1", "8.8.8.8"],
    "dns_test_host": "example.com",
    "tcp_test_host": "1.1.1.1",
    "tcp_test_port": 443,
    "http_test_urls": ["https://www.gstatic.com/generate_204", "https://www.cloudflare.com/cdn-cgi/trace"],
    "trigger_after_failures": 2,
    "high_latency_ms": 150,
    "loss_window": 20,
    "degraded_loss_pct": 25,
    "auto_report_on_recovery": True,
    "start_monitoring_on_launch": True,
}

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def load_config() -> Dict[str, Any]:
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        try:
            cfg.update(json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
        except Exception:
            pass
    else:
        CONFIG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    return cfg


def _decode_console(data: bytes) -> str:
    if not data:
        return ""
    encodings = ["utf-8"]
    if os.name == "nt":
        import ctypes
        encodings.append(f"cp{ctypes.windll.kernel32.GetOEMCP()}")
    encodings.extend([locale.getpreferredencoding(False), "cp866", "cp1251"])
    seen = set()
    for enc in encodings:
        if not enc or enc.lower() in seen:
            continue
        seen.add(enc.lower())
        try:
            return data.decode(enc, errors="strict")
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")


def run_hidden(cmd: list[str], timeout: float = 5.0) -> tuple[int, str, str]:
    try:
        cp = subprocess.run(
            cmd,
            capture_output=True,
            text=False,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
        return cp.returncode, _decode_console(cp.stdout), _decode_console(cp.stderr)
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as exc:
        return 125, "", str(exc)


def ping(host: str, timeout_ms: int) -> tuple[bool, Optional[float], str]:
    if not host:
        return False, None, "no host"
    if os.name == "nt":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
        timeout = max(2.0, timeout_ms / 1000 + 1.0)
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_ms / 1000))), host]
        timeout = max(2.0, timeout_ms / 1000 + 1.0)
    rc, out, err = run_hidden(cmd, timeout=timeout)
    text = out + "\n" + err
    # Windows can localize output, so match the language-independent time token variants.
    m = re.search(r"(?:time|время|temps|zeit|tiempo|tempo)\s*([=<])\s*(\d+(?:[\.,]\d+)?)\s*(?:ms|мс)\b", text, re.I)
    latency = None
    if m:
        latency = float(m.group(2).replace(",", "."))
        if m.group(1) == "<":
            latency /= 2
    # Windows ping may exit with code 0 for ICMP 'destination unreachable'.
    reply = m is not None or re.search(r"\bttl\s*[=:]\s*\d+", text, re.I) is not None
    ok = rc == 0 and (os.name != "nt" or reply)
    return ok, latency, text.strip()[-500:]


def tcp_connect(host: str, port: int, timeout: float) -> tuple[bool, Optional[float], str]:
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            ms = (time.perf_counter() - started) * 1000
            return True, round(ms, 1), "connected"
    except Exception as exc:
        return False, None, str(exc)


def dns_resolve(host: str, timeout: float) -> tuple[bool, Optional[float], str]:
    result: queue.Queue[tuple[bool, Optional[float], str]] = queue.Queue(maxsize=1)

    def worker() -> None:
        started = time.perf_counter()
        try:
            infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
            ips = sorted({x[4][0] for x in infos})
            result.put((True, round((time.perf_counter() - started) * 1000, 1), ", ".join(ips[:4])))
        except Exception as exc:
            result.put((False, None, str(exc)))

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    try:
        return result.get(timeout=timeout)
    except queue.Empty:
        return False, None, "DNS timeout"


def http_check(url: str, timeout: float) -> tuple[bool, Optional[float], str]:
    started = time.perf_counter()
    req = urllib.request.Request(url, headers={"User-Agent": f"{APP_NAME}/{APP_VERSION}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = getattr(resp, "status", 200)
            ms = (time.perf_counter() - started) * 1000
            return 200 <= code < 500, round(ms, 1), f"HTTP {code}"
    except Exception as exc:
        return False, None, str(exc)


def get_default_gateway() -> tuple[str, str, str]:
    """Return gateway, interface-ip, note."""
    if os.name == "nt":
        rc, out, err = run_hidden(["route", "print", "-4"], timeout=4)
        if rc == 0:
            candidates = []
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    try:
                        metric = int(parts[4])
                    except Exception:
                        metric = 999999
                    candidates.append((metric, parts[2], parts[3]))
            if candidates:
                candidates.sort(key=lambda x: x[0])
                _, gw, iface = candidates[0]
                return gw, iface, "route print"
        return "", "", err or "default route not found"
    rc, out, err = run_hidden(["ip", "route", "show", "default"], timeout=3)
    if rc == 0:
        m = re.search(r"default via (\S+).*?(?:src (\S+))?", out)
        if m:
            return m.group(1), m.group(2) or "", "ip route"
    return "", "", err or "default route not found"


def get_adapter_snapshot() -> Dict[str, Any]:
    snap: Dict[str, Any] = {
        "gateway": "",
        "interface_ip": "",
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "adapters": [],
        "dns_servers": [],
        "ipv6_present": False,
    }
    gw, iface, note = get_default_gateway()
    snap["gateway"] = gw
    snap["interface_ip"] = iface
    snap["route_note"] = note

    if os.name == "nt":
        ps = (
            "$ErrorActionPreference='SilentlyContinue';[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
            "Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,LinkSpeed,MacAddress,ifIndex | "
            "ConvertTo-Json -Compress"
        )
        rc, out, _ = run_hidden(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], timeout=8)
        if rc == 0 and out.strip():
            try:
                obj = json.loads(out)
                snap["adapters"] = obj if isinstance(obj, list) else [obj]
            except Exception:
                pass
        rc, out, _ = run_hidden(["ipconfig", "/all"], timeout=6)
        if rc == 0:
            dns = []
            lines = out.splitlines()
            capture_dns = False
            for line in lines:
                if re.search(r"DNS Servers|DNS-сервер", line, re.I):
                    capture_dns = True
                    val = line.split(":", 1)[-1].strip()
                    if val:
                        dns.append(val)
                    continue
                if capture_dns:
                    if line.startswith(" ") and line.strip() and ":" not in line.strip()[:20]:
                        dns.append(line.strip())
                    else:
                        capture_dns = False
                if "IPv6" in line and re.search(r"[0-9a-fA-F]{0,4}:[0-9a-fA-F:]", line):
                    snap["ipv6_present"] = True
            snap["dns_servers"] = list(dict.fromkeys(dns))[:8]
    return snap


def get_wifi_snapshot() -> Dict[str, Any]:
    if os.name != "nt":
        return {}
    rc, out, _ = run_hidden(["netsh", "wlan", "show", "interfaces"], timeout=5)
    if rc != 0:
        return {}
    result: Dict[str, Any] = {}
    patterns = {
        "ssid": r"^\s*SSID\s*:\s*(.+)$",
        "signal": r"^\s*(?:Signal|Сигнал)\s*:\s*(\d+)%",
        "radio": r"^\s*(?:Radio type|Тип радио)\s*:\s*(.+)$",
        "channel": r"^\s*(?:Channel|Канал)\s*:\s*(\d+)",
        "state": r"^\s*(?:State|Состояние)\s*:\s*(.+)$",
    }
    for line in out.splitlines():
        for key, pat in patterns.items():
            m = re.search(pat, line, re.I)
            if m and key not in result:
                val = m.group(1).strip()
                result[key] = int(val) if key in {"signal", "channel"} and val.isdigit() else val
    return result


@dataclass
class Snapshot:
    timestamp: str
    status: str
    cause_code: str
    cause_text: str
    confidence: str
    gateway: str = ""
    local_ip: str = ""
    gateway_ok: Optional[bool] = None
    gateway_ms: Optional[float] = None
    public_ok: Optional[bool] = None
    public_ms: Optional[float] = None
    public_target: str = ""
    tcp_ok: Optional[bool] = None
    tcp_ms: Optional[float] = None
    dns_ok: Optional[bool] = None
    dns_ms: Optional[float] = None
    http_ok: Optional[bool] = None
    http_ms: Optional[float] = None
    wifi_signal: Optional[int] = None
    packet_loss_pct: Optional[float] = None
    note: str = ""


class MonitorEngine:
    def __init__(self, cfg: Dict[str, Any], event_queue: queue.Queue):
        self.cfg = cfg
        self.q = event_queue
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.topology: Dict[str, Any] = {}
        self.wifi: Dict[str, Any] = {}
        self.protocol: Dict[str, Any] = {
            "dns_ok": None, "dns_ms": None, "dns_note": "not checked",
            "tcp_ok": None, "tcp_ms": None, "tcp_note": "not checked",
            "http_ok": None, "http_ms": None, "http_note": "not checked",
        }
        self.public_hist: Deque[bool] = deque(maxlen=int(cfg["loss_window"]))
        self.fail_streak = 0
        self.current_incident: Optional[Dict[str, Any]] = None
        self.last_cause_code = "INIT"
        self.last_snapshot: Optional[Snapshot] = None
        self._csv_ready = False
        DATA_DIR.mkdir(exist_ok=True)
        REPORT_DIR.mkdir(exist_ok=True)

    def start(self) -> None:
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._loop, name="network-monitor", daemon=True)
        self.thread.start()
        self._emit("engine", {"running": True})

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=3)
        self._emit("engine", {"running": False})

    def _emit(self, kind: str, payload: Dict[str, Any]) -> None:
        try:
            self.q.put_nowait((kind, payload))
        except queue.Full:
            pass

    def _write_event(self, kind: str, data: Dict[str, Any]) -> None:
        rec = {"timestamp": now_iso(), "kind": kind, **data}
        self._rotate_if_needed(EVENT_LOG, 5 * 1024 * 1024)
        with EVENT_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self._emit("event", rec)

    @staticmethod
    def _rotate_if_needed(path: Path, max_bytes: int) -> None:
        try:
            if path.exists() and path.stat().st_size > max_bytes:
                rotated = path.with_suffix(path.suffix + ".1")
                if rotated.exists():
                    rotated.unlink()
                path.replace(rotated)
        except Exception:
            pass

    def _write_sample(self, snap: Snapshot) -> None:
        self._rotate_if_needed(SAMPLE_LOG, 20 * 1024 * 1024)
        need_header = not SAMPLE_LOG.exists() or SAMPLE_LOG.stat().st_size == 0
        fields = list(asdict(snap).keys())
        with SAMPLE_LOG.open("a", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            if need_header:
                w.writeheader()
            w.writerow(asdict(snap))

    def _loop(self) -> None:
        next_protocol = 0.0
        next_topology = 0.0
        next_wifi = 0.0
        while not self.stop_event.is_set():
            cycle_start = time.monotonic()
            try:
                if cycle_start >= next_topology:
                    self.topology = get_adapter_snapshot()
                    next_topology = cycle_start + float(self.cfg["topology_interval_sec"])
                    self._emit("topology", self.topology)
                if cycle_start >= next_wifi:
                    self.wifi = get_wifi_snapshot()
                    next_wifi = cycle_start + float(self.cfg["wifi_interval_sec"])
                    self._emit("wifi", self.wifi)
                if cycle_start >= next_protocol:
                    self._run_protocol_checks()
                    next_protocol = cycle_start + float(self.cfg["protocol_interval_sec"])

                snap = self._run_fast_checks()
                self.last_snapshot = snap
                self._write_sample(snap)
                self._handle_trigger(snap)
                self._emit("snapshot", asdict(snap))
            except Exception as exc:
                self._write_event("internal_error", {"error": repr(exc)})

            elapsed = time.monotonic() - cycle_start
            sleep_for = max(0.2, float(self.cfg["fast_interval_sec"]) - elapsed)
            self.stop_event.wait(sleep_for)

    def _run_protocol_checks(self) -> None:
        timeout = float(self.cfg["socket_timeout_sec"])
        dns_ok, dns_ms, dns_note = dns_resolve(str(self.cfg["dns_test_host"]), timeout)
        tcp_ok, tcp_ms, tcp_note = tcp_connect(str(self.cfg["tcp_test_host"]), int(self.cfg["tcp_test_port"]), timeout)
        urls = self.cfg.get("http_test_urls") or [self.cfg.get("http_test_url", "https://www.gstatic.com/generate_204")]
        http_ok, http_ms, http_note = False, None, "not checked"
        http_notes = []
        for url in urls:
            ok, ms, note = http_check(str(url), timeout)
            http_notes.append(f"{url}: {note}")
            if ok:
                http_ok, http_ms, http_note = True, ms, note
                break
        if not http_ok:
            http_note = " | ".join(http_notes)[:400]
        self.protocol.update({
            "dns_ok": dns_ok, "dns_ms": dns_ms, "dns_note": dns_note,
            "tcp_ok": tcp_ok, "tcp_ms": tcp_ms, "tcp_note": tcp_note,
            "http_ok": http_ok, "http_ms": http_ms, "http_note": http_note,
        })

    def _run_fast_checks(self) -> Snapshot:
        gateway = str(self.topology.get("gateway") or "")
        local_ip = str(self.topology.get("interface_ip") or "")
        gw_ok, gw_ms, gw_note = ping(gateway, int(self.cfg["ping_timeout_ms"])) if gateway else (False, None, "no default gateway")

        public_ok = False
        public_ms = None
        public_target = ""
        public_notes = []
        for target in self.cfg.get("public_ping_targets", ["1.1.1.1"]):
            ok, ms, note = ping(str(target), int(self.cfg["ping_timeout_ms"]))
            public_notes.append(f"{target}: {'ok' if ok else 'fail'}")
            if ok:
                public_ok, public_ms, public_target = True, ms, str(target)
                break
        self.public_hist.append(public_ok)
        loss = 100.0 * (1 - (sum(self.public_hist) / len(self.public_hist))) if self.public_hist else None

        status, code, text, confidence = self._diagnose(
            gateway=gateway,
            gw_ok=gw_ok,
            public_ok=public_ok,
            dns_ok=self.protocol["dns_ok"],
            tcp_ok=self.protocol["tcp_ok"],
            http_ok=self.protocol["http_ok"],
            loss=loss,
            public_ms=public_ms,
        )
        wifi_signal = self.wifi.get("signal") if isinstance(self.wifi.get("signal"), int) else None
        note = f"GW: {gw_note[:90]} | {'; '.join(public_notes)} | DNS: {self.protocol['dns_note'][:90]} | TCP: {self.protocol['tcp_note'][:90]} | HTTP: {self.protocol['http_note'][:90]}"
        return Snapshot(
            timestamp=now_iso(), status=status, cause_code=code, cause_text=text, confidence=confidence,
            gateway=gateway, local_ip=local_ip,
            gateway_ok=gw_ok, gateway_ms=gw_ms,
            public_ok=public_ok, public_ms=public_ms, public_target=public_target,
            tcp_ok=self.protocol["tcp_ok"], tcp_ms=self.protocol["tcp_ms"],
            dns_ok=self.protocol["dns_ok"], dns_ms=self.protocol["dns_ms"],
            http_ok=self.protocol["http_ok"], http_ms=self.protocol["http_ms"],
            wifi_signal=wifi_signal, packet_loss_pct=round(loss, 1) if loss is not None else None,
            note=note,
        )

    def _diagnose(self, gateway: str, gw_ok: bool, public_ok: bool,
                  dns_ok: Optional[bool], tcp_ok: Optional[bool], http_ok: Optional[bool],
                  loss: Optional[float], public_ms: Optional[float]) -> tuple[str, str, str, str]:
        if not gateway:
            return "АВАРИЯ", "LOCAL_ROUTE", "Нет маршрута по умолчанию: адаптер отключён, нет DHCP/шлюза или проблема локальной конфигурации.", "высокая"

        # Internet working despite ICMP failure means ping is blocked, not an outage.
        if http_ok is True and dns_ok is True and tcp_ok is True:
            if not public_ok and not gw_ok:
                return "НОРМА", "ICMP_BLOCKED", "Интернет работает; ICMP/ping до шлюза и внешних узлов, вероятно, фильтруется.", "высокая"
            if loss is not None and len(self.public_hist) >= 6 and loss >= float(self.cfg["degraded_loss_pct"]):
                return "ДЕГРАДАЦИЯ", "PACKET_LOSS", f"Есть потери ICMP около {loss:.0f}%. Возможны Wi‑Fi помехи, перегрузка роутера или канала.", "средняя"
            if public_ms is not None and public_ms >= float(self.cfg["high_latency_ms"]):
                return "ДЕГРАДАЦИЯ", "HIGH_LATENCY", f"Высокая задержка до внешней сети: {public_ms:.0f} мс.", "средняя"
            return "НОРМА", "OK", "Шлюз, DNS, TCP и HTTP доступны.", "высокая"

        if not gw_ok and not public_ok and http_ok is not True:
            signal = self.wifi.get("signal")
            if isinstance(signal, int) and signal < 35:
                return "АВАРИЯ", "WIFI_OR_ROUTER", f"Шлюз недоступен, Wi‑Fi сигнал слабый ({signal}%). Вероятна локальная проблема Wi‑Fi/роутера.", "высокая"
            return "АВАРИЯ", "ROUTER_OR_LAN", "Шлюз/роутер не отвечает и внешняя сеть недоступна. Причина вероятнее в локальной сети, роутере, Wi‑Fi или кабеле.", "высокая"

        if gw_ok and not public_ok and tcp_ok is False and http_ok is False:
            return "АВАРИЯ", "ISP_OR_UPSTREAM", "Роутер доступен, но наружу нет TCP/HTTP. Вероятна проблема провайдера, WAN-соединения или внешней маршрутизации.", "высокая"

        if tcp_ok is True and dns_ok is False:
            return "АВАРИЯ", "DNS", "IP/TCP наружу работает, но DNS-имена не разрешаются. Проблема в DNS или его блокировке.", "высокая"

        if dns_ok is True and tcp_ok is True and http_ok is False:
            return "АВАРИЯ", "HTTP_TLS_PROXY", "DNS и TCP работают, но HTTP(S)-проверка не проходит. Возможны прокси, фильтрация, TLS/сертификаты или firewall.", "средняя"

        if gw_ok and tcp_ok is True:
            return "ДЕГРАДАЦИЯ", "PARTIAL_CONNECTIVITY", "Роутер и TCP доступны, но часть сетевых проверок не проходит. Это похоже на частичную фильтрацию или нестабильность.", "средняя"

        return "НЕОПРЕДЕЛЕНО", "UNKNOWN", "Проверки дают смешанный результат. Система сохранит детали и продолжит наблюдение.", "низкая"

    def _handle_trigger(self, snap: Snapshot) -> None:
        bad = snap.status in {"АВАРИЯ", "ДЕГРАДАЦИЯ"}
        if bad:
            self.fail_streak += 1
        else:
            self.fail_streak = 0

        threshold = int(self.cfg["trigger_after_failures"])
        if bad and self.fail_streak == threshold:
            self.current_incident = {
                "started": snap.timestamp,
                "cause_code": snap.cause_code,
                "cause_text": snap.cause_text,
                "status": snap.status,
            }
            self._write_event("incident_started", {**self.current_incident, "snapshot": asdict(snap)})
            self._emit("trigger", {"type": "start", **self.current_incident})

        if self.current_incident and snap.status == "НОРМА":
            incident = dict(self.current_incident)
            incident["ended"] = snap.timestamp
            incident["recovery_snapshot"] = asdict(snap)
            self._write_event("incident_recovered", incident)
            self._emit("trigger", {"type": "recovery", **incident})
            self.current_incident = None
            if self.cfg.get("auto_report_on_recovery", True):
                try:
                    report_path = generate_report()
                    self._emit("report", {"path": str(report_path)})
                except Exception as exc:
                    self._write_event("report_error", {"error": repr(exc)})

        if snap.cause_code != self.last_cause_code:
            self._write_event("state_changed", {
                "from": self.last_cause_code,
                "to": snap.cause_code,
                "status": snap.status,
                "cause_text": snap.cause_text,
            })
            self.last_cause_code = snap.cause_code


def read_events() -> list[Dict[str, Any]]:
    events = []
    for path in [EVENT_LOG.with_suffix(EVENT_LOG.suffix + ".1"), EVENT_LOG]:
        if not path.exists():
            continue
        try:
            with path.open("r", encoding="utf-8") as f:
                for line in f:
                    try:
                        events.append(json.loads(line))
                    except Exception:
                        pass
        except Exception:
            pass
    return events


def read_recent_samples(limit: int = 5000) -> list[Dict[str, Any]]:
    if not SAMPLE_LOG.exists():
        return []
    rows: Deque[Dict[str, Any]] = deque(maxlen=limit)
    try:
        with SAMPLE_LOG.open("r", encoding="utf-8-sig", newline="") as f:
            for row in csv.DictReader(f):
                rows.append(row)
    except Exception:
        return []
    return list(rows)


def generate_report(target_dir: Optional[Path] = None) -> Path:
    REPORT_DIR.mkdir(exist_ok=True)
    target_dir = target_dir or REPORT_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    events = read_events()
    samples = read_recent_samples()
    incidents = [e for e in events if e.get("kind") == "incident_started"]
    recoveries = [e for e in events if e.get("kind") == "incident_recovered"]
    causes = Counter(e.get("cause_code", "UNKNOWN") for e in incidents)
    status_counts = Counter(r.get("status", "") for r in samples)

    avg_latency = None
    lats = []
    losses = []
    for r in samples:
        try:
            if r.get("public_ms") not in {"", None, "None"}:
                lats.append(float(r["public_ms"]))
        except Exception:
            pass
        try:
            if r.get("packet_loss_pct") not in {"", None, "None"}:
                losses.append(float(r["packet_loss_pct"]))
        except Exception:
            pass
    if lats:
        avg_latency = sum(lats) / len(lats)

    rows_html = []
    for e in incidents[-100:][::-1]:
        snap = e.get("snapshot", {}) or {}
        rows_html.append(
            "<tr>"
            f"<td>{html.escape(str(e.get('timestamp','')))}</td>"
            f"<td>{html.escape(str(e.get('status','')))}</td>"
            f"<td>{html.escape(str(e.get('cause_code','')))}</td>"
            f"<td>{html.escape(str(e.get('cause_text','')))}</td>"
            f"<td>{html.escape(str(snap.get('gateway','')))}</td>"
            f"<td>{html.escape(str(snap.get('wifi_signal','')))}</td>"
            "</tr>"
        )

    cause_html = "".join(f"<li><b>{html.escape(k)}</b>: {v}</li>" for k, v in causes.most_common()) or "<li>Инцидентов пока нет.</li>"
    latest = samples[-1] if samples else {}
    report = f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><title>{APP_NAME} — отчёт</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;margin:28px;line-height:1.45;color:#18202a;background:#f6f8fb}}
.card{{background:white;border:1px solid #dfe5ec;border-radius:10px;padding:16px;margin:12px 0;box-shadow:0 1px 3px #00000012}}
h1,h2{{margin-top:0}} .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}}
.big{{font-size:26px;font-weight:700}} table{{border-collapse:collapse;width:100%;font-size:13px}} th,td{{border:1px solid #dde3ea;padding:8px;text-align:left;vertical-align:top}} th{{background:#eef2f6}} .muted{{color:#66717e}}
</style></head><body>
<h1>{APP_NAME}: отчёт по сети</h1><div class="muted">Сформирован: {html.escape(now_iso())}</div>
<div class="grid">
<div class="card"><div class="muted">Инцидентов</div><div class="big">{len(incidents)}</div></div>
<div class="card"><div class="muted">Восстановлений</div><div class="big">{len(recoveries)}</div></div>
<div class="card"><div class="muted">Средняя внешняя задержка</div><div class="big">{f'{avg_latency:.1f} мс' if avg_latency is not None else 'нет данных'}</div></div>
<div class="card"><div class="muted">Последний статус</div><div class="big">{html.escape(str(latest.get('status','нет данных')))}</div></div>
</div>
<div class="card"><h2>Что чаще было причиной</h2><ul>{cause_html}</ul></div>
<div class="card"><h2>Текущее состояние</h2>
<p><b>Диагноз:</b> {html.escape(str(latest.get('cause_text','нет данных')))}</p>
<p><b>Шлюз:</b> {html.escape(str(latest.get('gateway','')))} &nbsp; <b>Локальный IP:</b> {html.escape(str(latest.get('local_ip','')))}</p>
<p><b>Потери:</b> {html.escape(str(latest.get('packet_loss_pct','')))}% &nbsp; <b>Wi‑Fi:</b> {html.escape(str(latest.get('wifi_signal','')))}%</p>
</div>
<div class="card"><h2>Распределение измерений</h2><pre>{html.escape(json.dumps(status_counts, ensure_ascii=False, indent=2))}</pre></div>
<div class="card"><h2>Последние инциденты</h2><table><thead><tr><th>Время</th><th>Статус</th><th>Код</th><th>Причина</th><th>Шлюз</th><th>Wi‑Fi</th></tr></thead><tbody>{''.join(rows_html)}</tbody></table></div>
<div class="card"><h2>Как читать диагноз</h2><p><b>ROUTER_OR_LAN / WIFI_OR_ROUTER</b> — не доступен локальный шлюз. <b>ISP_OR_UPSTREAM</b> — шлюз доступен, но наружу нет TCP/HTTP. <b>DNS</b> — наружу по IP соединение есть, а имена не разрешаются. <b>HTTP_TLS_PROXY</b> — DNS/TCP есть, а HTTP(S) блокируется. <b>ICMP_BLOCKED</b> — ping запрещён, но интернет работает.</p></div>
</body></html>"""
    name = f"network_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    path = target_dir / name
    path.write_text(report, encoding="utf-8")
    return path


class App:
    def __init__(self, root: Tk):
        self.root = root
        self.root.title(f"{APP_NAME} {APP_VERSION}")
        self.root.geometry("980x700")
        self.root.minsize(860, 620)
        self.cfg = load_config()
        self.events: queue.Queue = queue.Queue(maxsize=200)
        self.engine = MonitorEngine(self.cfg, self.events)
        self.status_var = StringVar(value="Остановлен")
        self.diag_var = StringVar(value="Ожидание первого измерения…")
        self.details_var = StringVar(value="")
        self.running_var = BooleanVar(value=False)
        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(250, self.poll_events)
        if self.cfg.get("start_monitoring_on_launch", True):
            self.start()

    def _build_ui(self) -> None:
        outer = ttk.Frame(self.root, padding=12)
        outer.pack(fill=BOTH, expand=True)

        header = ttk.Frame(outer)
        header.pack(fill=X)
        ttk.Label(header, text=APP_NAME, font=("Segoe UI", 18, "bold")).pack(side=LEFT)
        ttk.Label(header, textvariable=self.status_var, font=("Segoe UI", 13, "bold")).pack(side=RIGHT)

        ttk.Separator(outer).pack(fill=X, pady=10)
        ttk.Label(outer, textvariable=self.diag_var, font=("Segoe UI", 12, "bold"), wraplength=930).pack(anchor="w")
        ttk.Label(outer, textvariable=self.details_var, wraplength=930).pack(anchor="w", pady=(5, 10))

        self.cards = ttk.Frame(outer)
        self.cards.pack(fill=X, pady=(0, 10))
        self.card_vars: Dict[str, StringVar] = {}
        for i, (key, title) in enumerate([
            ("router", "Роутер / шлюз"), ("internet", "Внешняя сеть"), ("dns", "DNS"),
            ("tcp", "TCP 443"), ("http", "HTTP(S)"), ("wifi", "Wi‑Fi сигнал"),
        ]):
            box = ttk.LabelFrame(self.cards, text=title, padding=8)
            box.grid(row=i // 3, column=i % 3, sticky="nsew", padx=4, pady=4)
            self.cards.columnconfigure(i % 3, weight=1)
            var = StringVar(value="—")
            self.card_vars[key] = var
            ttk.Label(box, textvariable=var, font=("Segoe UI", 11, "bold")).pack(anchor="center")

        btns = ttk.Frame(outer)
        btns.pack(fill=X, pady=(0, 10))
        self.start_btn = ttk.Button(btns, text="Старт", command=self.start)
        self.start_btn.pack(side=LEFT)
        self.stop_btn = ttk.Button(btns, text="Стоп", command=self.stop)
        self.stop_btn.pack(side=LEFT, padx=6)
        ttk.Button(btns, text="Сформировать отчёт", command=self.make_report).pack(side=LEFT, padx=6)
        ttk.Button(btns, text="Открыть папку данных", command=self.open_data).pack(side=LEFT, padx=6)
        ttk.Button(btns, text="Настройки", command=self.open_settings).pack(side=RIGHT)

        tabs = ttk.Notebook(outer)
        tabs.pack(fill=BOTH, expand=True)
        tab_events = ttk.Frame(tabs, padding=8)
        tab_net = ttk.Frame(tabs, padding=8)
        tabs.add(tab_events, text="События и триггеры")
        tabs.add(tab_net, text="Сеть")

        self.tree = ttk.Treeview(tab_events, columns=("time", "type", "text"), show="headings", height=14)
        self.tree.heading("time", text="Время")
        self.tree.heading("type", text="Тип")
        self.tree.heading("text", text="Событие")
        self.tree.column("time", width=165, anchor="w")
        self.tree.column("type", width=130, anchor="w")
        self.tree.column("text", width=610, anchor="w")
        yscroll = ttk.Scrollbar(tab_events, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)
        self.tree.pack(side=LEFT, fill=BOTH, expand=True)
        yscroll.pack(side=RIGHT, fill=Y)

        self.net_text = ttk.Treeview(tab_net, columns=("key", "value"), show="headings")
        self.net_text.heading("key", text="Параметр")
        self.net_text.heading("value", text="Значение")
        self.net_text.column("key", width=260)
        self.net_text.column("value", width=640)
        self.net_text.pack(fill=BOTH, expand=True)

        footer = ttk.Label(outer, text="Низкая нагрузка: ping каждые 5 с; DNS/TCP/HTTP раз в 15 с; топология раз в 60 с. Всё настраивается.", foreground="#666")
        footer.pack(fill=X, pady=(8, 0))

    def start(self) -> None:
        self.engine.start()
        self.running_var.set(True)
        self.status_var.set("Мониторинг запущен")

    def stop(self) -> None:
        self.engine.stop()
        self.running_var.set(False)
        self.status_var.set("Остановлен")

    def poll_events(self) -> None:
        try:
            for _ in range(50):
                kind, payload = self.events.get_nowait()
                if kind == "snapshot":
                    self.update_snapshot(payload)
                elif kind in {"event", "trigger"}:
                    self.add_event(kind, payload)
                elif kind == "topology":
                    self.update_network(payload)
                elif kind == "wifi":
                    self.update_network({"wifi": payload})
                elif kind == "report":
                    self.add_event("report", {"timestamp": now_iso(), "kind": "report", "path": payload.get("path")})
        except queue.Empty:
            pass
        self.root.after(250, self.poll_events)

    @staticmethod
    def fmt_check(ok: Optional[bool], ms: Optional[float] = None) -> str:
        if ok is None:
            return "—"
        if ok:
            return f"OK · {ms:.0f} мс" if isinstance(ms, (int, float)) else "OK"
        return "СБОЙ"

    def update_snapshot(self, p: Dict[str, Any]) -> None:
        self.status_var.set(p.get("status", "—"))
        self.diag_var.set(p.get("cause_text", ""))
        self.details_var.set(
            f"Причина: {p.get('cause_code','')} · уверенность: {p.get('confidence','')} · "
            f"потери: {p.get('packet_loss_pct','—')}% · шлюз: {p.get('gateway') or 'не найден'}"
        )
        self.card_vars["router"].set(self.fmt_check(p.get("gateway_ok"), p.get("gateway_ms")))
        self.card_vars["internet"].set(self.fmt_check(p.get("public_ok"), p.get("public_ms")))
        self.card_vars["dns"].set(self.fmt_check(p.get("dns_ok"), p.get("dns_ms")))
        self.card_vars["tcp"].set(self.fmt_check(p.get("tcp_ok"), p.get("tcp_ms")))
        self.card_vars["http"].set(self.fmt_check(p.get("http_ok"), p.get("http_ms")))
        sig = p.get("wifi_signal")
        self.card_vars["wifi"].set(f"{sig}%" if isinstance(sig, int) else "— / Ethernet")

    def add_event(self, kind: str, p: Dict[str, Any]) -> None:
        ts = p.get("timestamp", now_iso()).replace("T", " ")[:19]
        typ = p.get("kind", kind)
        if typ == "incident_started":
            text = f"СБОЙ: {p.get('cause_text','')}"
        elif typ == "incident_recovered":
            text = f"ВОССТАНОВЛЕНО: предыдущая причина {p.get('cause_code','')}"
        elif typ == "state_changed":
            text = f"Состояние {p.get('from')} → {p.get('to')}: {p.get('cause_text','')}"
        elif typ == "report":
            text = f"Отчёт: {p.get('path','')}"
        else:
            text = json.dumps(p, ensure_ascii=False)[:500]
        self.tree.insert("", 0, values=(ts, typ, text))
        children = self.tree.get_children()
        if len(children) > 300:
            for item in children[300:]:
                self.tree.delete(item)

    def update_network(self, p: Dict[str, Any]) -> None:
        if "wifi" in p:
            wifi = p["wifi"]
            items = [("Wi‑Fi " + str(k), v) for k, v in wifi.items()]
        else:
            items = [
                ("Шлюз", p.get("gateway")),
                ("Локальный IPv4", p.get("interface_ip")),
                ("Имя ПК", p.get("hostname")),
                ("IPv6 обнаружен", p.get("ipv6_present")),
                ("DNS-серверы", ", ".join(p.get("dns_servers", []))),
            ]
            for a in p.get("adapters", []) or []:
                items.append((f"Адаптер: {a.get('Name','?')}", f"{a.get('Status','')} · {a.get('LinkSpeed','')} · {a.get('InterfaceDescription','')}"))
        for item in self.net_text.get_children():
            vals = self.net_text.item(item, "values")
            if vals and any(str(k) == str(vals[0]) for k, _ in items):
                self.net_text.delete(item)
        for k, v in items:
            self.net_text.insert("", END, values=(k, v if v is not None else ""))

    def make_report(self) -> None:
        try:
            path = generate_report()
            messagebox.showinfo(APP_NAME, f"Отчёт создан:\n{path}")
            if os.name == "nt":
                os.startfile(path)  # type: ignore[attr-defined]
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Не удалось создать отчёт:\n{exc}")

    def open_data(self) -> None:
        DATA_DIR.mkdir(exist_ok=True)
        if os.name == "nt":
            os.startfile(DATA_DIR)  # type: ignore[attr-defined]
        else:
            messagebox.showinfo(APP_NAME, str(DATA_DIR))

    def open_settings(self) -> None:
        win = Toplevel(self.root)
        win.title("Настройки")
        win.geometry("480x430")
        frame = ttk.Frame(win, padding=12)
        frame.pack(fill=BOTH, expand=True)
        fields = [
            ("fast_interval_sec", "Быстрые проверки, сек"),
            ("protocol_interval_sec", "DNS/TCP/HTTP, сек"),
            ("topology_interval_sec", "Топология, сек"),
            ("wifi_interval_sec", "Wi‑Fi данные, сек"),
            ("ping_timeout_ms", "Таймаут ping, мс"),
            ("high_latency_ms", "Высокая задержка от, мс"),
            ("degraded_loss_pct", "Деградация при потерях, %"),
            ("trigger_after_failures", "Триггер после N сбоев"),
        ]
        vars_: Dict[str, StringVar] = {}
        for r, (key, label) in enumerate(fields):
            ttk.Label(frame, text=label).grid(row=r, column=0, sticky="w", pady=5)
            sv = StringVar(value=str(self.cfg.get(key, "")))
            vars_[key] = sv
            ttk.Entry(frame, textvariable=sv, width=18).grid(row=r, column=1, sticky="e", pady=5)

        def save() -> None:
            try:
                for key, sv in vars_.items():
                    val = float(sv.get())
                    if key in {"ping_timeout_ms", "high_latency_ms", "degraded_loss_pct", "trigger_after_failures", "loss_window"}:
                        val = int(val)
                    self.cfg[key] = val
                CONFIG_PATH.write_text(json.dumps(self.cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                self.engine.cfg = self.cfg
                messagebox.showinfo(APP_NAME, "Настройки сохранены. Новые интервалы применятся в следующих циклах.")
                win.destroy()
            except Exception:
                messagebox.showerror(APP_NAME, "Проверь числовые значения.")

        ttk.Button(frame, text="Сохранить", command=save).grid(row=len(fields), column=0, columnspan=2, pady=18)

    def on_close(self) -> None:
        try:
            self.engine.stop()
        finally:
            self.root.destroy()


def main() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    REPORT_DIR.mkdir(exist_ok=True)
    root = Tk()
    try:
        style = ttk.Style(root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
    except Exception:
        pass
    App(root)
    root.mainloop()


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        from smoke_checks import run_checks
        result = run_checks(sys.modules[__name__])
        if "--self-test-report" in sys.argv:
            Path(sys.argv[sys.argv.index("--self-test-report") + 1]).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        if sys.stdout:
            print(json.dumps(result, ensure_ascii=False))
    else:
        main()
