"""CLI do Endpoint Investigator.

Um único comando executa o fluxo completo, sem perguntas ao usuário:
collect -> normalize -> correlate -> report.

Uso:
    python3 -m investigator --dataset training/correlation --out reports/correlation
    sudo python3 -m investigator --live --out reports/live

``--dump-snapshot`` para depois da normalização: grava ``snapshot.json`` (o
Snapshot que a correlação recebe) em ``--out`` e imprime um resumo de contagens.

Código de saída: 0 = sem RISCO, 1 = ao menos um RISCO, 2 = erro de execução.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import collect_dataset
from . import correlate
from . import normalize
from . import report


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

    # Uma exceção não tratada sairia com código 1, que aqui significa "há RISCO":
    # qualquer falha de execução é convertida explicitamente em código 2.
    try:
        snap = normalize.build_snapshot(raw)

        if args.dump_snapshot:
            path = _dump_snapshot(snap, out_dir)
            print(_summary(snap))
            print(f"\nSnapshot gravado em: {path}")
            return 0

        findings, notes = correlate.analyze(snap)
        return report.render(snap, findings, out_dir, notes)
    except Exception as exc:  # noqa: BLE001
        print(f"Erro de execução: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
