"""Relatório: terminal, ``report.md`` e ``report.json``.

Todo achado é impresso no mesmo formato de quatro partes — EVIDÊNCIA,
INTERPRETAÇÃO, HIPÓTESE, EVIDÊNCIA AUSENTE — para que o leitor nunca precise
adivinhar o que foi observado e o que foi inferido.

Código de saída: 1 se houver ao menos um RISCO, 0 caso contrário.
"""

from __future__ import annotations

import json
import re
import textwrap
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from .model import Finding, Snapshot, TimelineEvent

_WIDTH = 100

_CONCLUSIONS = {
    "RISCO": "condição que permite abuso; exploração não comprovada",
    "CONFIG_INADEQUADA": "configuração inadequada, sem relação de privilégio demonstrada",
    "INCONCLUSIVO": "evidência insuficiente para concluir",
    "CONTEXTO_OK": "contexto verificado, sem achado",
}
_KIND_LABELS = {"service": "serviço", "process": "processo", "permission": "permissão",
                "log": "log", "socket": "socket", "cron": "cron"}
_LOG_EVENT_KINDS = ("login", "session", "service_start", "service_stop")
_MAX_TIMELINE = 30
_MAX_GAPS = 12


# --------------------------------------------------------------------------- #
# Dados comuns aos três formatos                                               #
# --------------------------------------------------------------------------- #
def _sources(finding: Finding) -> list[str]:
    kinds = sorted({e.kind for e in finding.evidence if e.kind})
    return [_KIND_LABELS.get(k, k) for k in kinds]


def _verdict(finding: Finding) -> str:
    sources = _sources(finding)
    plural = "fonte" if len(sources) == 1 else "fontes"
    return (f"{finding.conclusion} ({_CONCLUSIONS.get(finding.conclusion, '')}) — "
            f"relação observada com confiança {finding.confidence} "
            f"({len(sources)} {plural}: {', '.join(sources)})")


def _timeline(snap: Snapshot, findings: list[Finding]) -> tuple[list[TimelineEvent], int]:
    """Eventos de log + mtime dos arquivos citados em achados; (eventos, omitidos)."""
    cited = {word for f in findings if f.conclusion != "CONTEXTO_OK"
             for link in f.chain for word in link.split()}
    events = [e for e in snap.timeline
              if e.kind in _LOG_EVENT_KINDS or (e.kind == "file_mtime" and e.subject in cited)]
    if len(events) > _MAX_TIMELINE:
        # Coleta ao vivo traz centenas de eventos de serviço: ficam os logins e o
        # que os achados citam; o restante segue em report.json.
        relevant = [e for e in events if e.kind in ("login", "session") or e.subject in cited]
        events_shown = (relevant or events)[-_MAX_TIMELINE:]
        return events_shown, len(events) - len(events_shown)
    return events, 0


def _gaps(snap: Snapshot) -> list[str]:
    """Lacunas para exibição: repetições do mesmo tipo (só muda o PID) viram uma linha."""
    groups: dict[str, list[str]] = {}
    for gap in snap.gaps:
        groups.setdefault(re.sub(r"\d+", "N", gap), []).append(gap)
    shown: list[str] = []
    for pattern, items in groups.items():
        shown += items if len(items) <= 3 else [f"{pattern}  (×{len(items)})"]
    return shown


def _event_text(event: TimelineEvent) -> str:
    detail = ""
    if event.kind == "login":
        detail = f" ({event.detail.get('method')} de {event.detail.get('ip')})"
    return f"{event.ts or '?':<19}  {event.kind:<13}  {event.subject}{detail}"


def _summary(snap: Snapshot, findings: list[Finding]) -> dict:
    counts = Counter(f.conclusion for f in findings)
    return {
        "processes": len(snap.processes), "services": len(snap.services),
        "files": len(snap.files), "logs": len(snap.logs), "gaps": len(snap.gaps),
        "conclusions": {name: counts.get(name, 0) for name in _CONCLUSIONS},
    }


# --------------------------------------------------------------------------- #
# Terminal                                                                     #
# --------------------------------------------------------------------------- #
def _wrap(label: str, text: str) -> str:
    indent = " " * 15
    return textwrap.fill(text, width=_WIDTH, initial_indent=f"{label:<15}",
                         subsequent_indent=indent)


def _bullet(text: str, indent: str = "  - ") -> str:
    return textwrap.fill(text, width=_WIDTH, initial_indent=indent,
                         subsequent_indent=" " * len(indent))


def _format_finding(finding: Finding) -> str:
    head = f"[{finding.severity.upper()}] {finding.id} {finding.title}"
    lines = [f"{head}  ({finding.correlation})",
             _wrap("Cadeia:", " → ".join(finding.chain)),
             "EVIDÊNCIA (observado)"]
    pad = min(max((len(e.src) for e in finding.evidence), default=0), 28)
    for e in finding.evidence:
        lines.append(textwrap.fill(e.text, width=_WIDTH,
                                   initial_indent=f"  - {e.src:<{pad}}  ",
                                   subsequent_indent=" " * (pad + 6)))
    lines.append(_wrap("INTERPRETAÇÃO", finding.interpretation))
    lines.append(_wrap("HIPÓTESE", finding.hypothesis))
    lines.append("EVIDÊNCIA AUSENTE")
    lines += [_bullet(m) for m in finding.missing] or ["  - (nada além do observado)"]
    lines.append(_wrap("CONCLUSÃO:", _verdict(finding)))
    return "\n".join(lines)


def _text(snap: Snapshot, findings: list[Finding], notes: list[str]) -> str:
    summary = _summary(snap, findings)
    issues = [f for f in findings if f.conclusion != "CONTEXTO_OK"]
    checks = [f for f in findings if f.conclusion == "CONTEXTO_OK"]
    events, omitted = _timeline(snap, findings)
    rule, thin = "=" * _WIDTH, "-" * _WIDTH

    out = [rule, "ENDPOINT INVESTIGATOR — RESULTADO DA INVESTIGAÇÃO",
           f"Fonte: {snap.source}   Host: {snap.host}   Coleta: {snap.taken_at}   "
           f"Como root: {'sim' if snap.ran_as_root else 'NÃO (visibilidade parcial)'}",
           thin, "RESUMO",
           f"  Observado: {summary['processes']} processos · {summary['services']} serviços · "
           f"{summary['files']} arquivos · {summary['logs']} linhas de log",
           "  Conclusões: " + " · ".join(f"{k} {v}" for k, v in summary["conclusions"].items()),
           "  Os achados descrevem condições e hipóteses a revisar; nenhum prova exploração.",
           "", thin, f"ACHADOS ({len(issues)})", thin]
    if not issues:
        out.append("  Nenhuma relação que mereça investigação foi encontrada nas evidências disponíveis.")
    for finding in issues:
        out += [_format_finding(finding), ""]

    out += [thin, f"VERIFICAÇÕES SEM ACHADO ({len(checks)})", thin]
    for finding in checks:
        out.append(_bullet(f"{finding.id} {finding.title} ({finding.correlation}) — "
                           f"base: {', '.join(e.src for e in finding.evidence)}"))
    if not checks:
        out.append("  (nenhuma)")

    out += ["", thin, "NÃO AVALIADO / OBSERVAÇÕES", thin]
    out += [_bullet(n) for n in notes] or ["  (nada a registrar)"]

    out += ["", thin, "LINHA DO TEMPO", thin]
    if omitted:
        out.append(f"  (… {omitted} outros eventos omitidos; lista completa em report.json)")
    out += [f"  {_event_text(e)}   [{e.src}]" for e in events] or ["  (sem eventos)"]

    out += ["", thin, f"LACUNAS DE COLETA / LIMITAÇÕES DESTA EXECUÇÃO ({len(snap.gaps)})", thin]
    gaps = _gaps(snap)
    out += [_bullet(g) for g in gaps[:_MAX_GAPS]] or ["  (nenhuma registrada)"]
    if len(gaps) > _MAX_GAPS:
        out.append(f"  (… mais {len(gaps) - _MAX_GAPS}; lista completa em report.json)")
    out.append(rule)
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Markdown                                                                     #
# --------------------------------------------------------------------------- #
def _markdown(snap: Snapshot, findings: list[Finding], notes: list[str]) -> str:
    summary = _summary(snap, findings)
    issues = [f for f in findings if f.conclusion != "CONTEXTO_OK"]
    checks = [f for f in findings if f.conclusion == "CONTEXTO_OK"]
    events, omitted = _timeline(snap, findings)

    out = ["# Endpoint Investigator — resultado da investigação", "",
           f"- **Fonte:** {snap.source}", f"- **Host:** {snap.host}",
           f"- **Coleta:** {snap.taken_at}",
           f"- **Como root:** {'sim' if snap.ran_as_root else 'não (visibilidade parcial)'}", "",
           "## Resumo", "",
           f"Observado: {summary['processes']} processos, {summary['services']} serviços, "
           f"{summary['files']} arquivos, {summary['logs']} linhas de log.", "",
           "| Conclusão | Qtde | Significado |", "|---|---|---|"]
    out += [f"| {name} | {summary['conclusions'][name]} | {meaning} |"
            for name, meaning in _CONCLUSIONS.items()]
    out += ["", "> Os achados descrevem condições e hipóteses a revisar; nenhum prova exploração.",
            "", f"## Achados ({len(issues)})", ""]
    if not issues:
        out += ["Nenhuma relação que mereça investigação foi encontrada nas evidências disponíveis.", ""]
    for f in issues:
        out += [f"### [{f.severity.upper()}] {f.id} {f.title} ({f.correlation})", "",
                f"**Cadeia:** {' → '.join(f.chain)}", "", "**Evidência (observado)**", ""]
        out += [f"- `{e.src}` — {e.text}" for e in f.evidence]
        out += ["", f"**Interpretação:** {f.interpretation}", "",
                f"**Hipótese:** {f.hypothesis}", "", "**Evidência ausente**", ""]
        out += [f"- {m}" for m in f.missing] or ["- (nada além do observado)"]
        out += ["", f"**Conclusão:** {_verdict(f)}", ""]

    out += [f"## Verificações sem achado ({len(checks)})", ""]
    out += [f"- **{f.id}** {f.title} ({f.correlation}) — base: "
            f"{', '.join(f'`{e.src}`' for e in f.evidence)}" for f in checks] or ["(nenhuma)"]
    out += ["", "## Não avaliado / observações", ""]
    out += [f"- {n}" for n in notes] or ["(nada a registrar)"]
    out += ["", "## Linha do tempo", ""]
    if omitted:
        out += [f"_{omitted} outros eventos omitidos; lista completa em `report.json`._", ""]
    if events:
        out += ["| Horário | Evento | Sujeito | Origem |", "|---|---|---|---|"]
        out += [f"| {e.ts} | {e.kind} | {e.subject} | `{e.src}` |" for e in events]
    else:
        out.append("(sem eventos)")
    out += ["", f"## Lacunas de coleta / limitações desta execução ({len(snap.gaps)})", ""]
    gaps = _gaps(snap)
    out += [f"- {g}" for g in gaps[:_MAX_GAPS]] or ["(nenhuma registrada)"]
    if len(gaps) > _MAX_GAPS:
        out.append(f"- … mais {len(gaps) - _MAX_GAPS}; lista completa em `report.json`")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- #
# JSON                                                                         #
# --------------------------------------------------------------------------- #
def _json(snap: Snapshot, findings: list[Finding], notes: list[str]) -> dict:
    return {
        "source": snap.source, "host": snap.host, "taken_at": snap.taken_at,
        "ran_as_root": snap.ran_as_root,
        "summary": _summary(snap, findings),
        "findings": [asdict(f) for f in findings],
        "not_evaluated": notes,
        "timeline": [asdict(e) for e in snap.timeline
                     if e.kind in _LOG_EVENT_KINDS or e.kind == "file_mtime"],
        "gaps": snap.gaps,
    }


# --------------------------------------------------------------------------- #
# Entrada                                                                      #
# --------------------------------------------------------------------------- #
def render(snap: Snapshot, findings: list[Finding], out_dir: Path,
           notes: Optional[list[str]] = None) -> int:
    """Imprime o relatório, grava report.md e report.json e devolve o código de saída."""
    notes = notes or []
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(_text(snap, findings, notes))
    (out_dir / "report.md").write_text(_markdown(snap, findings, notes), encoding="utf-8")
    (out_dir / "report.json").write_text(
        json.dumps(_json(snap, findings, notes), indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nRelatórios gravados em: {out_dir / 'report.md'} e {out_dir / 'report.json'}")

    return 1 if any(f.conclusion == "RISCO" for f in findings) else 0
