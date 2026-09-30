"""Coletor do modo dataset (formato do professor).

Lê os quatro arquivos de um diretório de dataset e devolve registros crus, já
com proveniência (`src`) linha a linha, mais os eventos de log estruturados.
A montagem do Snapshot e os fatos derivados ficam em ``normalize.py``.

Quirks do dataset tratados aqui (ver §2 do plano):
  * ``journal.log`` não tem ano: obtido de ``processes.csv`` ou ``metadata.json``.
  * Os CSVs anexam ``-03:00`` a horários wall-clock em UTC; o journal traz o
    mesmo wall-clock sem offset. Normalizamos tudo para wall-clock *naive*
    (sem offset), de modo que as comparações temporais sejam diretas.
  * A coluna ``timestamp`` de ``processes.csv`` é o horário de observação da
    linha, não o horário de início do processo.
"""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from .model import LogEvent


# Mapa fixo de meses (evita dependência de locale ao parsear "Sep 14").
_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# Sep 14 09:00:00 srv-app-01 systemd[1]: Started ssh.service - ...
_JOURNAL_RE = re.compile(
    r"^(\w{3} \d{2} \d{2}:\d{2}:\d{2}) (\S+) ([^\[:]+)(?:\[(\d+)\])?: (.*)$"
)


@dataclass
class RawDataset:
    """Registros crus de um dataset, antes da normalização."""

    source: str = "dataset"
    host: str = "desconhecido"
    year: Optional[int] = None
    taken_at: Optional[str] = None            # wall-clock naive da primeira observação
    ran_as_root: bool = True                  # dataset: assume-se completo; live: euid==0
    group_members: dict = field(default_factory=dict)  # grupo -> set de usuários (só live)
    processes: list[dict] = field(default_factory=list)
    permissions: list[dict] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    logs: list[LogEvent] = field(default_factory=list)
    sockets: list[dict] = field(default_factory=list)   # extras (só live)
    cron: list[dict] = field(default_factory=list)       # extras (só live)
    metadata: dict = field(default_factory=dict)
    gaps: list[str] = field(default_factory=list)


def to_naive_iso(value: str) -> Optional[str]:
    """Converte um horário ISO (com ou sem offset) para wall-clock naive.

    Ex.: "2026-09-14T09:03:20-03:00" -> "2026-09-14T09:03:20".
    Retorna None se não for parseável.
    """
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is not None:
        dt = dt.replace(tzinfo=None)
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def _read_metadata(dataset_dir: Path, gaps: list[str]) -> dict:
    meta_path = dataset_dir / "metadata.json"
    if not meta_path.exists():
        gaps.append("metadata.json ausente do dataset")
        return {}
    try:
        return json.loads(meta_path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        gaps.append(f"metadata.json ilegível: {exc}")
        return {}


def _resolve_year(processes: list[dict], metadata: dict, gaps: list[str]) -> int:
    """Descobre o ano (o journal não o traz). processes.csv primeiro, depois metadata."""
    for row in processes:
        ts = row.get("timestamp")
        if ts:
            try:
                return datetime.fromisoformat(ts).year
            except ValueError:
                pass
    generated = metadata.get("generated_at")
    if generated:
        try:
            return datetime.fromisoformat(generated).year
        except ValueError:
            pass
    fallback = datetime.now().year
    gaps.append(f"Ano do journal indeterminado; assumido {fallback}")
    return fallback


def _parse_processes(dataset_dir: Path, gaps: list[str]) -> list[dict]:
    path = dataset_dir / "processes.csv"
    if not path.exists():
        gaps.append("processes.csv ausente do dataset")
        return []
    rows: list[dict] = []
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for i, row in enumerate(reader, start=2):  # linha 1 = cabeçalho
            row = dict(row)
            row["src"] = f"processes.csv:{i}"
            rows.append(row)
    return rows


def _parse_permissions(dataset_dir: Path, gaps: list[str]) -> list[dict]:
    path = dataset_dir / "permissions.csv"
    if not path.exists():
        gaps.append("permissions.csv ausente do dataset")
        return []
    rows: list[dict] = []
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for i, row in enumerate(reader, start=2):
            row = dict(row)
            row["src"] = f"permissions.csv:{i}"
            rows.append(row)
    return rows


def _parse_services(dataset_dir: Path, gaps: list[str]) -> list[dict]:
    """services.txt: pula o cabeçalho e usa split(maxsplit=3).

    Não usa larguras fixas, porque nomes de unidade longos as quebrariam.
    """
    path = dataset_dir / "services.txt"
    if not path.exists():
        gaps.append("services.txt ausente do dataset")
        return []
    rows: list[dict] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines, start=1):
        if i == 1:
            continue  # cabeçalho "UNIT ACTIVE USER EXECSTART"
        if not line.strip():
            continue
        parts = line.split(maxsplit=3)
        if len(parts) < 4:
            gaps.append(f"services.txt:{i} com colunas insuficientes: {line!r}")
            continue
        unit, active, user, exec_start = parts
        rows.append({
            "unit": unit,
            "active": active,
            "user": user,
            "exec_start": exec_start,
            "src": f"services.txt:{i}",
        })
    return rows


def _parse_journal(dataset_dir: Path, year: int, gaps: list[str]) -> tuple[list[LogEvent], Optional[str]]:
    path = dataset_dir / "journal.log"
    if not path.exists():
        gaps.append("journal.log ausente do dataset")
        return [], None
    events: list[LogEvent] = []
    host: Optional[str] = None
    lines = path.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        m = _JOURNAL_RE.match(line)
        if not m:
            gaps.append(f"journal.log:{i} fora do formato esperado: {line!r}")
            continue
        ts_raw, line_host, ident, pid_str, message = m.groups()
        if host is None:
            host = line_host
        ts = _journal_ts_to_iso(ts_raw, year)
        events.append(LogEvent(
            ts=ts,
            ident=ident.strip(),
            pid=int(pid_str) if pid_str else None,
            unit=None,                      # o modo dataset não traz _SYSTEMD_UNIT
            message=message,
            src=f"journal.log:{i}",
        ))
    return events, host


def _journal_ts_to_iso(ts_raw: str, year: int) -> Optional[str]:
    """"Sep 14 09:00:00" + ano -> "2026-09-14T09:00:00" (wall-clock naive)."""
    try:
        mon_abbr, day_str, clock = ts_raw.split(" ")
        month = _MONTHS[mon_abbr]
        day = int(day_str)
        hh, mm, ss = (int(x) for x in clock.split(":"))
        return datetime(year, month, day, hh, mm, ss).strftime("%Y-%m-%dT%H:%M:%S")
    except (ValueError, KeyError):
        return None


def collect(dataset_dir: str | Path) -> RawDataset:
    """Lê um diretório de dataset e devolve os registros crus + logs estruturados."""
    dataset_dir = Path(dataset_dir)
    gaps: list[str] = []
    if not dataset_dir.is_dir():
        raise FileNotFoundError(f"Diretório de dataset não encontrado: {dataset_dir}")

    metadata = _read_metadata(dataset_dir, gaps)
    processes = _parse_processes(dataset_dir, gaps)
    permissions = _parse_permissions(dataset_dir, gaps)
    services = _parse_services(dataset_dir, gaps)
    year = _resolve_year(processes, metadata, gaps)
    logs, host = _parse_journal(dataset_dir, year, gaps)

    taken_at = None
    if processes:
        taken_at = to_naive_iso(processes[0].get("timestamp", ""))

    # Limitações estruturais do modo dataset (o plano pede que sejam declaradas).
    gaps.append("Modo dataset: sem UID/EUID nem participação em grupos")
    gaps.append("Modo dataset: sem crontabs/timers")

    return RawDataset(
        source="dataset",
        host=host or metadata.get("host", "desconhecido"),
        year=year,
        taken_at=taken_at,
        processes=processes,
        permissions=permissions,
        services=services,
        logs=logs,
        metadata=metadata,
        gaps=gaps,
    )
