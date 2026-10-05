"""Normalização: registros crus -> Snapshot com fatos derivados.

Converte a coleta (dataset ou live) em um único ``Snapshot``. Aqui vivem:

  * extração de caminhos (exe/script) a partir de cmdline/ExecStart;
  * flags de modo (world/group-writable, SUID, SGID);
  * ``nonroot_writable`` e sua justificativa (o conceito central de permissão),
    inclusive o caso do diretório-pai gravável;
  * mapeamento processo -> serviço, registrando o método que casou;
  * ligação log -> processo/serviço;
  * cadeias de ancestralidade (``Process.ancestry``);
  * linha do tempo tipada (``Snapshot.timeline``).
"""

from __future__ import annotations

import re
import shlex
from datetime import datetime
from typing import Optional

from .collect_dataset import to_naive_iso
from .model import (
    FileInfo,
    LogEvent,
    Process,
    Service,
    Snapshot,
    TimelineEvent,
)

# Prefixos especiais de ExecStart do systemd (systemd.service(5)).
_SYSTEMD_PREFIX_CHARS = set("-@+!:")

# Basenames tratados como interpretadores: o script é o 1º argumento absoluto.
_INTERPRETERS = {
    "sh", "bash", "dash", "zsh", "ksh", "ash",
    "perl", "ruby", "node", "nodejs", "php", "awk", "lua",
}

# Localizações graváveis por usuário comum (usadas depois por Sardou; aqui só
# ajudam a documentar). Mantidas como referência.
USER_WRITABLE_DIRS = ("/tmp", "/dev/shm", "/var/tmp", "/home")


# --------------------------------------------------------------------------- #
# Caminhos                                                                     #
# --------------------------------------------------------------------------- #
def strip_systemd_prefix(token: str) -> str:
    """Remove prefixos especiais do systemd (``-@+!:``) do início do executável."""
    i = 0
    while i < len(token) and token[i] in _SYSTEMD_PREFIX_CHARS:
        i += 1
    return token[i:]


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def is_interpreter(exe: str) -> bool:
    """True se o basename do executável é um interpretador conhecido."""
    base = _basename(exe)
    return base in _INTERPRETERS or base.startswith("python")


def split_argv(cmd: str) -> list[str]:
    """Divide uma linha de comando em argv, tolerante a aspas malformadas."""
    if not cmd:
        return []
    try:
        return shlex.split(cmd)
    except ValueError:
        return cmd.split()


def extract_paths(cmd: str) -> tuple[Optional[str], Optional[str]]:
    """De uma cmdline/ExecStart, devolve (exe, script).

    * ``exe`` é argv[0] sem os prefixos do systemd.
    * se ``exe`` é um interpretador, ``script`` é o primeiro argumento que
      começa com ``/`` (caminho absoluto).
    """
    argv = split_argv(cmd)
    if not argv:
        return None, None
    exe = strip_systemd_prefix(argv[0])
    script = None
    if is_interpreter(exe):
        for arg in argv[1:]:
            if arg.startswith("/"):
                script = arg
                break
    return exe or None, script


# --------------------------------------------------------------------------- #
# Modo de arquivo / permissões                                                 #
# --------------------------------------------------------------------------- #
def parse_mode(mode_str: str) -> Optional[int]:
    """Converte "0777"/"4755" (octal) em inteiro. None se inválido."""
    try:
        return int(mode_str, 8)
    except (ValueError, TypeError):
        return None


def mode_flags(mode: int) -> dict[str, bool]:
    """Extrai world/group-writable, SUID e SGID de um modo inteiro."""
    return {
        "world_writable": bool(mode & 0o002),
        "group_writable": bool(mode & 0o020),
        "suid": bool(mode & 0o4000),
        "sgid": bool(mode & 0o2000),
    }


def _parent_dirs(path: str) -> list[str]:
    """Diretórios ancestrais de um caminho, do mais próximo à raiz."""
    parts = path.rstrip("/").split("/")
    parents: list[str] = []
    for i in range(len(parts) - 1, 0, -1):
        p = "/".join(parts[:i])
        parents.append(p if p else "/")
    return parents


def _group_has_nonroot(group: str, group_members: Optional[dict]) -> Optional[bool]:
    """No modo live, True se o grupo tem membro != root; None se desconhecido."""
    if not group_members or group not in group_members:
        return None
    return any(u != "root" for u in group_members[group])


def _self_nonroot_writable(fi: FileInfo, live: bool,
                           group_members: Optional[dict]) -> tuple[bool, str]:
    """Um arquivo/diretório é gravável por não-root por seus próprios metadados?

    Ordem das razões (conforme o plano): others:w, group:w (grupo != root),
    owner != root.
    """
    if fi.world_writable:
        return True, "others:w"
    if fi.group_writable and fi.group != "root":
        if live:
            has = _group_has_nonroot(fi.group, group_members)
            if has:
                return True, f"group:w grupo={fi.group} (membro não-root)"
            # has is False/None -> não confirmável como gravável por não-root
        else:
            return True, (f"group:w grupo={fi.group} "
                          f"(dataset: grupo pode conter usuários não-root)")
    if fi.owner != "root":
        return True, f"owner={fi.owner}"
    return False, ""


def compute_nonroot_writable(fi: FileInfo, files: dict[str, FileInfo], live: bool,
                             group_members: Optional[dict]) -> tuple[bool, str]:
    """Combina o próprio arquivo e qualquer diretório-pai gravável por não-root."""
    self_w, reason = _self_nonroot_writable(fi, live, group_members)
    if self_w:
        return True, reason
    for parent_path in _parent_dirs(fi.path):
        parent = files.get(parent_path)
        if parent is None:
            continue
        pw, _ = _self_nonroot_writable(parent, live, group_members)
        # Sticky bit (ex.: /tmp 1777): só o dono do arquivo ou do diretório remove
        # ou renomeia entradas, então o+w no diretório não permite substituir um
        # arquivo de root.
        if pw and parent.mode & 0o1000 and parent.owner == "root":
            continue
        if pw:
            return True, f"dir {parent_path} {format(parent.mode, '04o')}"
    return False, ""


# --------------------------------------------------------------------------- #
# Construção das entidades                                                     #
# --------------------------------------------------------------------------- #
def _build_files(raw_permissions: list[dict], live: bool,
                 group_members: Optional[dict], gaps: list[str]) -> dict[str, FileInfo]:
    files: dict[str, FileInfo] = {}
    for row in raw_permissions:
        path = row.get("path")
        if not path:
            continue
        mode = parse_mode(row.get("mode", ""))
        if mode is None:
            gaps.append(f"Modo ilegível para {path} ({row.get('src', '')})")
            continue
        flags = mode_flags(mode)
        fi = FileInfo(
            path=path,
            type=row.get("type", "file"),
            owner=row.get("owner", ""),
            group=row.get("group", ""),
            mode=mode,
            mtime=to_naive_iso(row.get("mtime", "")) or row.get("mtime"),
            world_writable=flags["world_writable"],
            group_writable=flags["group_writable"],
            suid=flags["suid"],
            sgid=flags["sgid"],
            nonroot_writable=None,
            nonroot_reason="",
            src=row.get("src", ""),
        )
        files[path] = fi
    # Segunda passada: nonroot_writable depende de os pais já existirem.
    for fi in files.values():
        writable, reason = compute_nonroot_writable(fi, files, live, group_members)
        fi.nonroot_writable = writable
        fi.nonroot_reason = reason
    return files


def _service_paths(exec_start: str, unit_file: Optional[str]) -> tuple[Optional[str], Optional[str], list[str]]:
    exe, script = extract_paths(exec_start)
    paths: list[str] = []
    if exe and exe.startswith("/"):
        paths.append(exe)
    if script:
        paths.append(script)
    if unit_file:
        paths.append(unit_file)
    return exe, script, paths


def _build_services(raw_services: list[dict]) -> dict[str, Service]:
    services: dict[str, Service] = {}
    for row in raw_services:
        unit = row.get("unit")
        if not unit:
            continue
        exec_start = row.get("exec_start", "")
        unit_file = row.get("unit_file")
        _exe, _script, paths = _service_paths(exec_start, unit_file)
        svc = Service(
            unit=unit,
            active=row.get("active", ""),
            user=row.get("user", ""),
            exec_start=exec_start,
            main_pid=row.get("main_pid"),
            unit_file=unit_file,
            paths=paths,
            src=row.get("src", ""),
        )
        services[unit] = svc
    return services


def _build_processes(raw_processes: list[dict], gaps: list[str]) -> dict[int, Process]:
    processes: dict[int, Process] = {}
    for row in raw_processes:
        try:
            pid = int(row["pid"])
            ppid = int(row["ppid"])
        except (KeyError, ValueError):
            gaps.append(f"Processo com pid/ppid inválido: {row.get('src', row)}")
            continue
        cmdline = row.get("cmd", row.get("cmdline", ""))
        exe_raw = row.get("exe")
        if exe_raw:
            exe = exe_raw
            _, script = extract_paths(cmdline)
        else:
            exe, script = extract_paths(cmdline)
        proc = Process(
            pid=pid,
            ppid=ppid,
            user=row.get("user", ""),
            uid=row.get("uid"),
            euid=row.get("euid"),
            state=row.get("stat", row.get("state", "")),
            cmdline=cmdline,
            exe=exe,
            script=script,
            start=row.get("start"),
            unit=None,
            unit_method=None,
            ancestry=[],
            src=row.get("src", ""),
        )
        processes[pid] = proc
    return processes


# --------------------------------------------------------------------------- #
# Ancestralidade                                                               #
# --------------------------------------------------------------------------- #
def build_ancestry(processes: dict[int, Process], gaps: list[str]) -> None:
    """Preenche Process.ancestry subindo os PPIDs até o PID 1.

    Protege contra ciclos e contra pais ausentes do snapshot (registrados em gaps).
    """
    reported_missing: set[tuple[int, int]] = set()
    for proc in processes.values():
        chain: list[int] = []
        seen: set[int] = {proc.pid}
        current = proc.ppid
        while current and current not in seen:
            chain.append(current)
            seen.add(current)
            parent = processes.get(current)
            if parent is None:
                key = (current, proc.pid)
                if key not in reported_missing:
                    gaps.append(f"PPID {current} de PID {proc.pid} ausente do snapshot")
                    reported_missing.add(key)
                break
            if current == 1:
                break
            current = parent.ppid
        proc.ancestry = chain


# --------------------------------------------------------------------------- #
# Mapeamento processo -> serviço                                               #
# --------------------------------------------------------------------------- #
def _unit_base(unit: str) -> str:
    """"backup-agent.service" -> "backup-agent"."""
    return unit[:-8] if unit.endswith(".service") else unit


def map_processes_to_services(processes: dict[int, Process],
                              services: dict[str, Service]) -> None:
    """Associa processos a unidades, registrando o método (unit_method)."""
    # Índices auxiliares.
    by_mainpid = {s.main_pid: u for u, s in services.items() if s.main_pid}
    svc_scripts: dict[str, str] = {}
    for unit, svc in services.items():
        _exe, script = extract_paths(svc.exec_start)
        if script:
            svc_scripts[unit] = script

    for proc in processes.values():
        # 1. cgroup (live): o coletor live grava cgroup_unit no raw -> exposto em exe? não.
        cg = getattr(proc, "_cgroup_unit", None)
        if cg and cg in services:
            proc.unit, proc.unit_method = cg, "cgroup"
            continue
        # 2. MainPID (live)
        if proc.pid in by_mainpid:
            proc.unit, proc.unit_method = by_mainpid[proc.pid], "mainpid"
            continue
        # 3. cmd == ExecStart com ppid 1
        matched = False
        if proc.ppid == 1:
            for unit, svc in services.items():
                if svc.exec_start and svc.exec_start == proc.cmdline:
                    proc.unit, proc.unit_method = unit, "execstart"
                    matched = True
                    break
        if matched:
            continue
        # 4. mesmo caminho de script
        if proc.script:
            for unit, script in svc_scripts.items():
                if script == proc.script:
                    proc.unit, proc.unit_method = unit, "script"
                    matched = True
                    break
        if matched:
            continue
        # 6. nome-base da unidade == basename do exe (fraco)
        if proc.exe:
            base = _basename(proc.exe)
            for unit in services:
                if _unit_base(unit) == base:
                    proc.unit, proc.unit_method = unit, "name"
                    matched = True
                    break

    # 5. herdado de um ancestral mapeado (após a 1ª passada).
    for proc in processes.values():
        if proc.unit:
            continue
        for anc_pid in proc.ancestry:
            anc = processes.get(anc_pid)
            if anc and anc.unit:
                proc.unit, proc.unit_method = anc.unit, "ancestor"
                break


# --------------------------------------------------------------------------- #
# Ligação log -> processo/serviço                                              #
# --------------------------------------------------------------------------- #
def link_logs(logs: list[LogEvent], processes: dict[int, Process],
              services: dict[str, Service]) -> None:
    """Preenche LogEvent.unit quando possível (ident, PID, 'Started X.service')."""
    unit_by_base = {_unit_base(u): u for u in services}
    for ev in logs:
        if ev.unit:
            continue
        # por ident == nome-base de uma unidade (ex.: backup-agent[2417])
        if ev.ident in unit_by_base:
            ev.unit = unit_by_base[ev.ident]
            continue
        # por PID que já está mapeado a uma unidade
        if ev.pid is not None:
            proc = processes.get(ev.pid)
            if proc and proc.unit:
                ev.unit = proc.unit
                continue
        # systemd[1]: Started/Starting X.service
        m = re.search(r"\b(?:Started|Starting) (\S+\.service)", ev.message)
        if m:
            ev.unit = m.group(1)


# --------------------------------------------------------------------------- #
# Linha do tempo                                                               #
# --------------------------------------------------------------------------- #
_RE_LOGIN = re.compile(r"Accepted (\S+) for (\S+) from (\S+)")
_RE_SESSION = re.compile(r"New session \d+ of user (\S+)")
_RE_SVC_START = re.compile(r"\b(?:Started|Starting) (\S+\.service)")
_RE_SVC_STOP = re.compile(r"(\S+\.service): (?:Deactivated|Stopped)|Stopped (\S+\.service)")


def build_timeline(logs: list[LogEvent], processes: dict[int, Process],
                   files: dict[str, FileInfo]) -> list[TimelineEvent]:
    """Converte logs, inícios de processo e mtimes em eventos tipados e ordenados."""
    events: list[TimelineEvent] = []

    for ev in logs:
        msg = ev.message
        m = _RE_LOGIN.search(msg)
        if m:
            method, user, ip = m.group(1), m.group(2), m.group(3)
            events.append(TimelineEvent(
                ts=ev.ts, kind="login", subject=user,
                detail={"user": user, "ip": ip, "method": method}, src=ev.src))
            continue
        m = _RE_SESSION.search(msg)
        if m:
            user = m.group(1).rstrip(".")
            events.append(TimelineEvent(
                ts=ev.ts, kind="session", subject=user,
                detail={"user": user}, src=ev.src))
            continue
        m = _RE_SVC_STOP.search(msg)
        if m:
            unit = m.group(1) or m.group(2)
            events.append(TimelineEvent(
                ts=ev.ts, kind="service_stop", subject=unit,
                detail={"unit": unit}, src=ev.src))
            continue
        m = _RE_SVC_START.search(msg)
        if m:
            events.append(TimelineEvent(
                ts=ev.ts, kind="service_start", subject=m.group(1),
                detail={"unit": m.group(1)}, src=ev.src))
            continue

    # Inícios de processo (live traz Process.start).
    for proc in processes.values():
        if proc.start:
            events.append(TimelineEvent(
                ts=proc.start, kind="process_start", subject=str(proc.pid),
                detail={"pid": proc.pid, "cmd": proc.cmdline}, src=proc.src))

    # mtime de cada arquivo.
    for fi in files.values():
        if fi.mtime:
            events.append(TimelineEvent(
                ts=fi.mtime, kind="file_mtime", subject=fi.path,
                detail={"path": fi.path}, src=fi.src))

    events.sort(key=_timeline_sort_key)
    return events


def _timeline_sort_key(ev: TimelineEvent):
    """Ordena por tempo; eventos sem ts vão para o fim."""
    if not ev.ts:
        return (1, datetime.max, ev.kind)
    try:
        return (0, datetime.fromisoformat(ev.ts), ev.kind)
    except ValueError:
        return (1, datetime.max, ev.kind)


# --------------------------------------------------------------------------- #
# Montagem do Snapshot                                                         #
# --------------------------------------------------------------------------- #
def build_snapshot(raw) -> Snapshot:
    """Transforma uma coleta crua (dataset ou live) em um Snapshot normalizado."""
    gaps = list(getattr(raw, "gaps", []))
    live = getattr(raw, "source", "dataset") == "live"
    group_members = getattr(raw, "group_members", None)

    files = _build_files(raw.permissions, live, group_members, gaps)
    services = _build_services(raw.services)
    processes = _build_processes(raw.processes, gaps)

    # cgroup: se o raw de processo trouxe cgroup_unit, anexa como atributo auxiliar.
    for row in raw.processes:
        try:
            pid = int(row["pid"])
        except (KeyError, ValueError):
            continue
        if row.get("cgroup_unit") and pid in processes:
            setattr(processes[pid], "_cgroup_unit", row["cgroup_unit"])

    build_ancestry(processes, gaps)
    map_processes_to_services(processes, services)

    logs = list(raw.logs)
    link_logs(logs, processes, services)
    timeline = build_timeline(logs, processes, files)

    snap = Snapshot(
        source=getattr(raw, "source", "dataset"),
        host=getattr(raw, "host", "desconhecido"),
        taken_at=getattr(raw, "taken_at", None),
        ran_as_root=getattr(raw, "ran_as_root", True),
        processes=processes,
        services=services,
        files=files,
        logs=logs,
        timeline=timeline,
        sockets=list(getattr(raw, "sockets", [])),
        cron=list(getattr(raw, "cron", [])),
        gaps=gaps,
    )
    return snap
