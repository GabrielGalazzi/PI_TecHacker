"""Coletor do modo live (máquina GNU/Linux; rodar com ``sudo`` no Kali).

Observa o endpoint atual por interfaces do sistema operacional e devolve os
mesmos registros crus que o coletor de dataset, para reuso da mesma normalização.

Fontes (ver referências do README):
  * ``/proc/<pid>/{status,cmdline,exe,cgroup,stat}`` + ``/proc/stat`` (btime)
  * ``systemctl list-units`` / ``systemctl show``
  * ``os.lstat`` + ``pwd``/``grp`` para permissões (por contexto, não varredura)
  * ``journalctl -o json``
  * ``ss`` (sockets) e ``/etc/crontab`` + ``/etc/cron.d/*`` (extras)

Tudo é protegido por try/except: sem root, a ferramenta ainda roda e lista
lacunas (``gaps``) em vez de quebrar.
"""

from __future__ import annotations

import grp
import json
import os
import pwd
import re
import stat
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

from .collect_dataset import RawDataset
from .model import LogEvent


_CLK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
_CGROUP_UNIT_RE = re.compile(r"/([^/]+\.service)")
_ARGV_RE = re.compile(r"argv\[\]=(.*?) ;")
_TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})")
_SS_USERS_RE = re.compile(r'users:\(\("([^"]+)",pid=(\d+),fd=(\d+)\)')


def _run(cmd: list[str], gaps: list[str], timeout: int = 30) -> Optional[str]:
    """Executa um comando e devolve stdout; registra lacuna em caso de falha."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (FileNotFoundError, subprocess.SubprocessError) as exc:
        gaps.append(f"comando indisponível: {' '.join(cmd[:2])} ({exc})")
        return None
    if proc.returncode != 0 and not proc.stdout:
        gaps.append(f"falha em {' '.join(cmd[:2])}: rc={proc.returncode} {proc.stderr.strip()[:120]}")
        return None
    return proc.stdout


def _uid_to_name(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def _gid_to_name(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def _boot_time(gaps: list[str]) -> Optional[int]:
    try:
        for line in Path("/proc/stat").read_text().splitlines():
            if line.startswith("btime "):
                return int(line.split()[1])
    except OSError as exc:
        gaps.append(f"/proc/stat ilegível: {exc}")
    return None


def _epoch_to_naive_iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch).strftime("%Y-%m-%dT%H:%M:%S")


# --------------------------------------------------------------------------- #
# Processos                                                                    #
# --------------------------------------------------------------------------- #
def _collect_processes(btime: Optional[int], gaps: list[str]) -> list[dict]:
    rows: list[dict] = []
    for proc_dir in Path("/proc").glob("[0-9]*"):
        pid = int(proc_dir.name)
        try:
            cmdline_raw = (proc_dir / "cmdline").read_bytes()
        except (OSError, ProcessLookupError):
            continue
        cmdline = cmdline_raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        if not cmdline:
            continue  # kernel thread
        row: dict = {"pid": str(pid), "cmd": cmdline, "src": f"/proc/{pid}/status"}
        try:
            _parse_status(proc_dir, row)
        except PermissionError:
            gaps.append(f"/proc/{pid}/status sem permissão")
        except (OSError, ProcessLookupError):
            continue
        # readlink exe
        try:
            row["exe"] = os.readlink(proc_dir / "exe")
        except (OSError, PermissionError):
            gaps.append(f"/proc/{pid}/exe não resolvido (permissão ou processo encerrado)")
        # cgroup -> unidade
        try:
            cg = (proc_dir / "cgroup").read_text()
            m = _CGROUP_UNIT_RE.search(cg)
            if m:
                row["cgroup_unit"] = m.group(1)
        except (OSError, PermissionError):
            pass
        # start time via stat campo 22 + btime
        if btime is not None:
            start = _proc_start(proc_dir, btime)
            if start:
                row["start"] = start
        rows.append(row)
    return rows


def _parse_status(proc_dir: Path, row: dict) -> None:
    text = (proc_dir / "status").read_text()
    for line in text.splitlines():
        if line.startswith("PPid:"):
            row["ppid"] = line.split()[1]
        elif line.startswith("State:"):
            row["state"] = line.split()[1]
        elif line.startswith("Uid:"):
            parts = line.split()
            uid, euid = int(parts[1]), int(parts[2])
            row["uid"], row["euid"] = uid, euid
            row["user"] = _uid_to_name(uid)
        elif line.startswith("Gid:"):
            pass
    row.setdefault("ppid", "0")


def _proc_start(proc_dir: Path, btime: int) -> Optional[str]:
    try:
        stat = (proc_dir / "stat").read_text()
    except (OSError, PermissionError):
        return None
    # comm pode conter espaços/parênteses: usar o conteúdo após o último ')'.
    rparen = stat.rfind(")")
    if rparen == -1:
        return None
    tokens = stat[rparen + 2:].split()
    # tokens[0] = campo 3 (state); starttime = campo 22 -> índice 19.
    if len(tokens) <= 19:
        return None
    try:
        starttime_ticks = int(tokens[19])
    except ValueError:
        return None
    epoch = btime + starttime_ticks / _CLK_TCK
    return _epoch_to_naive_iso(epoch)


# --------------------------------------------------------------------------- #
# Serviços                                                                     #
# --------------------------------------------------------------------------- #
def _collect_services(gaps: list[str]) -> list[dict]:
    out = _run(["systemctl", "list-units", "--type=service", "--state=running",
                "--no-legend", "--plain"], gaps)
    if not out:
        return []
    units = [line.split()[0] for line in out.splitlines() if line.strip()]
    if not units:
        return []
    show = _run(["systemctl", "show", *units, "-p",
                 "Id,ActiveState,User,Group,MainPID,ExecStart,FragmentPath,ActiveEnterTimestamp"],
                gaps)
    if not show:
        return []
    rows: list[dict] = []
    for block in show.split("\n\n"):
        props: dict[str, str] = {}
        for line in block.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                props[k] = v
        unit = props.get("Id")
        if not unit:
            continue
        exec_start = _parse_execstart(props.get("ExecStart", ""))
        rows.append({
            "unit": unit,
            "active": props.get("ActiveState", ""),
            "user": props.get("User", ""),
            "exec_start": exec_start,
            "main_pid": _int_or_none(props.get("MainPID")),
            "unit_file": props.get("FragmentPath") or None,
            "active_enter": _systemctl_ts(props.get("ActiveEnterTimestamp", "")),
            "src": f"systemctl show {unit}",
        })
    return rows


def _parse_execstart(value: str) -> str:
    """Extrai argv[] do formato '{ path=… ; argv[]=… ; … }'."""
    m = _ARGV_RE.search(value)
    if m:
        return m.group(1).strip()
    m2 = re.search(r"path=(\S+)", value)
    return m2.group(1) if m2 else value.strip()


def _systemctl_ts(value: str) -> Optional[str]:
    m = _TS_RE.search(value)
    return f"{m.group(1)}T{m.group(2)}" if m else None


def _int_or_none(v: Optional[str]) -> Optional[int]:
    try:
        n = int(v)
        return n if n != 0 else None
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# Permissões por contexto                                                      #
# --------------------------------------------------------------------------- #
def _with_parents(path: str) -> list[str]:
    parts = path.rstrip("/").split("/")
    out = [path]
    for i in range(len(parts) - 1, 0, -1):
        p = "/".join(parts[:i])
        out.append(p if p else "/")
    return out


def _collect_files(processes: list[dict], services: list[dict],
                   cron: list[dict], gaps: list[str]) -> list[dict]:
    candidates: list[str] = []

    def add(path: Optional[str]) -> None:
        if path and path.startswith("/"):
            candidates.append(path)

    for svc in services:
        for tok in svc["exec_start"].split():
            if tok.startswith("/"):
                add(tok)
        add(svc.get("unit_file"))
    for proc in processes:
        add(proc.get("exe"))
        for tok in proc["cmd"].split():
            if tok.startswith("/"):
                add(tok)
    for entry in cron:
        for path in entry.get("paths", []):
            add(path)

    # Contexto fixo e pequeno (não é varredura): arquivos de identidade do sistema
    # e binários instalados localmente, onde um SUID fora do padrão apareceria.
    for path in ("/etc/passwd", "/etc/shadow", "/etc/sudoers"):
        add(path)
    for local_dir in ("/usr/local/bin", "/usr/local/sbin"):
        try:
            for entry in sorted(os.scandir(local_dir), key=lambda e: e.name):
                add(entry.path)
        except OSError:
            pass

    # expande com diretórios-pai e remove duplicatas preservando ordem
    seen: set[str] = set()
    expanded: list[str] = []
    for cand in candidates:
        for p in _with_parents(cand):
            if p not in seen:
                seen.add(p)
                expanded.append(p)

    rows: list[dict] = []
    for path in expanded:
        try:
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode):
                # O modo de um link simbólico é sempre 0777 e o kernel o ignora:
                # quem decide o acesso são as permissões do alvo.
                st = os.stat(path)
        except FileNotFoundError:
            continue
        except PermissionError:
            gaps.append(f"lstat sem permissão: {path}")
            continue
        except OSError:
            continue
        is_dir = stat.S_ISDIR(st.st_mode)
        rows.append({
            "path": path,
            "type": "directory" if is_dir else "file",
            "owner": _uid_to_name(st.st_uid),
            "group": _gid_to_name(st.st_gid),
            "mode": format(st.st_mode & 0o7777, "04o"),
            "mtime": _epoch_to_naive_iso(st.st_mtime),
            "src": path,
        })
    return rows


# --------------------------------------------------------------------------- #
# Logs                                                                         #
# --------------------------------------------------------------------------- #
def _collect_logs(gaps: list[str]) -> list[LogEvent]:
    out = _run(["journalctl", "-o", "json", "--since", "-24h", "-n", "5000", "--no-pager"], gaps)
    if not out:
        gaps.append("journalctl indisponível ou sem entradas nas últimas 24h")
        return []
    events: list[LogEvent] = []
    for i, line in enumerate(out.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        ts = None
        rt = rec.get("__REALTIME_TIMESTAMP")
        if rt:
            try:
                ts = _epoch_to_naive_iso(int(rt) / 1_000_000)
            except (ValueError, OSError):
                ts = None
        message = rec.get("MESSAGE", "")
        if isinstance(message, list):  # journald pode entregar bytes como lista de ints
            try:
                message = bytes(message).decode("utf-8", "replace")
            except (ValueError, TypeError):
                message = str(message)
        events.append(LogEvent(
            ts=ts,
            ident=rec.get("SYSLOG_IDENTIFIER", ""),
            pid=_int_or_none(rec.get("_PID")),
            unit=rec.get("_SYSTEMD_UNIT"),
            message=message,
            src=f"journalctl:{i}",
        ))
    return events


# --------------------------------------------------------------------------- #
# Extras: sockets e cron                                                       #
# --------------------------------------------------------------------------- #
def _collect_sockets(gaps: list[str]) -> list[dict]:
    sockets: list[dict] = []
    for args, state in (
        (["ss", "-tulpnH"], "listening"),
        (["ss", "-tupnH", "state", "established"], "established"),
    ):
        out = _run(args, gaps)
        if not out:
            continue
        for line in out.splitlines():
            if not line.strip():
                continue
            m = _SS_USERS_RE.search(line)
            fields = line.split()
            # ss -H colunas: Netid State Recv-Q Send-Q Local:Port Peer:Port [Process]
            local = fields[4] if len(fields) > 4 else ""
            peer = fields[5] if len(fields) > 5 else ""
            sockets.append({
                "state": state,
                "local": local,
                "peer": peer,
                "process": m.group(1) if m else None,
                "pid": int(m.group(2)) if m else None,
            })
    return sockets


def _collect_cron(gaps: list[str]) -> list[dict]:
    entries: list[dict] = []
    files = [Path("/etc/crontab")] + sorted(Path("/etc/cron.d").glob("*")) \
        if Path("/etc/cron.d").is_dir() else [Path("/etc/crontab")]
    for cron_file in files:
        if not cron_file.is_file():
            continue
        try:
            lines = cron_file.read_text().splitlines()
        except (OSError, PermissionError) as exc:
            gaps.append(f"cron ilegível {cron_file}: {exc}")
            continue
        for i, line in enumerate(lines, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue  # vazio ou comentário
            parts = line.split()
            if "=" in parts[0]:
                continue  # linha de ambiente (ex.: PATH=/usr/bin)
            # formato /etc/crontab e cron.d: m h dom mon dow user command
            if len(parts) < 7:
                continue
            user = parts[5]
            command = " ".join(parts[6:])
            paths = [tok for tok in command.split() if tok.startswith("/")]
            entries.append({
                "user": user,
                "command": command,
                "paths": paths,
                "src": f"{cron_file}:{i}",
            })
    return entries


def _group_members() -> dict[str, set]:
    members: dict[str, set] = {}
    try:
        for g in grp.getgrall():
            members.setdefault(g.gr_name, set()).update(g.gr_mem)
    except OSError:
        return members
    # membros por grupo primário
    try:
        gid_to_name = {g.gr_gid: g.gr_name for g in grp.getgrall()}
        for u in pwd.getpwall():
            name = gid_to_name.get(u.pw_gid)
            if name:
                members.setdefault(name, set()).add(u.pw_name)
    except OSError:
        pass
    return members


# --------------------------------------------------------------------------- #
# Entrada                                                                      #
# --------------------------------------------------------------------------- #
def collect() -> RawDataset:
    gaps: list[str] = []
    ran_as_root = (os.geteuid() == 0)
    if not ran_as_root:
        gaps.append("Execução sem root: visibilidade parcial (/proc de outros usuários, "
                    "permissões e alguns logs podem faltar)")

    btime = _boot_time(gaps)
    processes = _collect_processes(btime, gaps)
    services = _collect_services(gaps)
    cron = _collect_cron(gaps)
    files = _collect_files(processes, services, cron, gaps)
    logs = _collect_logs(gaps)
    sockets = _collect_sockets(gaps)

    try:
        host = os.uname().nodename
    except OSError:
        host = "desconhecido"

    return RawDataset(
        source="live",
        host=host,
        year=datetime.now().year,
        taken_at=datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        ran_as_root=ran_as_root,
        group_members=_group_members(),
        processes=processes,
        permissions=files,
        services=services,
        logs=logs,
        sockets=sockets,
        cron=cron,
        metadata={},
        gaps=gaps,
    )
