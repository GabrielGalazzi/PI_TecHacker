"""CLI do Endpoint Investigator.

Criado por Galazzi (coleta/normalização + ``--dump-snapshot``); Sardou estende
para o fluxo completo collect -> normalize -> correlate -> report.

Uso (lado Galazzi):
    python3 -m investigator --dataset training/correlation --dump-snapshot
    sudo python3 -m investigator --live --dump-snapshot

``--dump-snapshot`` grava ``snapshot.json`` (o Snapshot normalizado) em ``--out``
e imprime um resumo de contagens. É o que esta metade entrega e permite a Sardou
inspecionar exatamente o que recebe.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import collect_dataset
from . import normalize


def _collect(args):
    """Executa o coletor apropriado e devolve a coleta crua."""
    if args.dataset:
        return collect_dataset.collect(args.dataset)
    # import tardio: só carrega o coletor live quando necessário.
    from . import collect_live
    return collect_live.collect()


def _summary(snap) -> str:
    n_mapped = sum(1 for p in snap.processes.values() if p.unit)
    lines = [
        f"source        : {snap.source}",
        f"host          : {snap.host}",
        f"taken_at      : {snap.taken_at}",
        f"ran_as_root   : {snap.ran_as_root}",
        f"processes     : {len(snap.processes)} (mapeados a serviço: {n_mapped})",
        f"services      : {len(snap.services)}",
        f"files         : {len(snap.files)}",
        f"logs          : {len(snap.logs)}",
        f"timeline      : {len(snap.timeline)} eventos",
        f"sockets       : {len(snap.sockets)}",
        f"cron          : {len(snap.cron)}",
        f"gaps          : {len(snap.gaps)}",
    ]
    return "\n".join(lines)


def _dump_snapshot(snap, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "snapshot.json"
    path.write_text(
        json.dumps(snap.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="investigator",
        description="Coleta, normaliza, correlaciona e relata o estado de um endpoint Linux.",
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--dataset", metavar="DIR", help="Diretório de dataset (formato do professor).")
    src.add_argument("--live", action="store_true", help="Coleta ao vivo (Kali; use sudo para visão completa).")
    parser.add_argument("--out", metavar="DIR", default="reports", help="Diretório de saída.")
    parser.add_argument("--dump-snapshot", action="store_true",
                        help="Grava snapshot.json e imprime um resumo (sem análise).")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    out_dir = Path(args.out)

    try:
        raw = _collect(args)
    except (FileNotFoundError, OSError) as exc:
        print(f"Erro de coleta: {exc}", file=sys.stderr)
        return 2

    snap = normalize.build_snapshot(raw)

    if args.dump_snapshot:
        path = _dump_snapshot(snap, out_dir)
        print(_summary(snap))
        print(f"\nSnapshot gravado em: {path}")
        return 0

    # Fluxo completo (Sardou, S4). Import tardio para não exigir os módulos de
    # análise nesta metade; se ainda não existirem, cai no dump do snapshot.
    try:
        from . import correlate, report  # noqa: F401
    except ImportError:
        path = _dump_snapshot(snap, out_dir)
        print(_summary(snap))
        print("\n[aviso] módulos de análise (correlate/report) ainda não disponíveis;")
        print("        execute com --dump-snapshot ou aguarde a Parte 2 (Sardou).")
        print(f"Snapshot gravado em: {path}")
        return 0

    # Gancho para a Parte 2: correlate.run(snap) -> findings; report.render(...).
    findings = correlate.run(snap)
    return report.render(snap, findings, out_dir)


if __name__ == "__main__":
    raise SystemExit(main())
