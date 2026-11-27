"""The host's health, as an unprivileged process can read it.

Everything comes from ``/proc``, ``/sys`` and ``statvfs``, which any account
reads: ``clixz-mcpd`` computes it itself, without relaying anywhere. Boxyz is a
4 GiB Raspberry Pi whose crash of 2026-09-30 was seen only by its effects:
memory pressure and swap are the first things to look at.
"""

from __future__ import annotations

import os
from pathlib import Path

PROC = Path("/proc")
THERMAL = Path("/sys/class/thermal")


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def _meminfo(text: str | None) -> dict[str, int]:
    out = {}
    for line in (text or "").splitlines():
        key, _, rest = line.partition(":")
        parts = rest.split()
        if parts and parts[0].isdigit():
            out[key] = int(parts[0]) * 1024  # kB → bytes
    return out


def _pressure(text: str | None) -> dict[str, dict[str, float]]:
    out: dict[str, dict[str, float]] = {}
    for line in (text or "").splitlines():
        kind, *fields = line.split()
        values = dict(f.split("=", 1) for f in fields if "=" in f)
        out[kind] = {k: float(values[k]) for k in ("avg10", "avg60", "avg300") if k in values}
    return out


def _disk(path: Path) -> dict | None:
    try:
        st = os.statvfs(path)
    except OSError:
        return None
    total, free = st.f_blocks * st.f_frsize, st.f_bavail * st.f_frsize
    return {"path": str(path), "total": total, "available": free,
            "used_percent": round((total - free) / total * 100, 1) if total else None}


def _temperatures(thermal: Path) -> dict[str, float]:
    out = {}
    for zone in sorted(thermal.glob("thermal_zone*")):
        raw, kind = _read(zone / "temp"), _read(zone / "type")
        if raw and raw.strip().lstrip("-").isdigit():
            out[(kind or zone.name).strip()] = int(raw) / 1000
    return out


def host_status(root_dir: Path, proc: Path = PROC, thermal: Path = THERMAL) -> dict:
    mem = _meminfo(_read(proc / "meminfo"))
    load = (_read(proc / "loadavg") or "").split()
    uptime = (_read(proc / "uptime") or "").split()
    disks = [d for d in (_disk(Path("/")), _disk(root_dir)) if d]
    return {
        "uptime_seconds": int(float(uptime[0])) if uptime else None,
        "load": [float(x) for x in load[:3]] if len(load) >= 3 else None,
        "cpus": os.cpu_count(),
        "memory": {"total": mem.get("MemTotal"), "available": mem.get("MemAvailable"),
                   "swap_total": mem.get("SwapTotal"), "swap_free": mem.get("SwapFree")},
        "pressure": {kind: _pressure(_read(proc / "pressure" / kind))
                     for kind in ("cpu", "memory", "io")},
        "disks": list({d["path"]: d for d in disks}.values()),
        "temperatures_celsius": _temperatures(thermal),
    }
