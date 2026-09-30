# Relatório da Parte 1 (Galazzi) — Coleta & Normalização

Registro do que foi implementado, dos bugs corrigidos e de tudo o que se afastou
do texto original do `IMPLEMENTATION_PLAN.md`. **Nenhuma alteração ao pipeline foi
feita por conveniência**: cada mudança abaixo é correção de bug ou detalhe de
implementação exigido para o pipeline funcionar como o plano descreve.

## O que foi entregue

| Item | Arquivo(s) | Situação |
|---|---|---|
| G0 — correção do gerador + `--scenario` | `generate_dataset.py` | ✅ |
| G1 — contrato `Snapshot` | `investigator/model.py` | ✅ (lado Finding deixado para Sardou) |
| G2 — coletor de dataset | `investigator/collect_dataset.py` | ✅ |
| G3 + G3b — normalização, mapeamentos, ancestralidade, timeline | `investigator/normalize.py` | ✅ |
| G4 — CLI mínima + `--dump-snapshot` | `investigator/__main__.py` | ✅ |
| G5 — coletor live | `investigator/collect_live.py` | ✅ (testado sem root nesta máquina) |
| G6 — 4 cenários + lab + testes | `generate_dataset.py`, `lab/*.sh`, `tests/test_normalize.py` | ✅ (lab pendente de execução na VM) |
| G7 — docs | `README.md`, `docs/documento_tecnico.md` | ✅ (seções de Galazzi) |

## Bugs corrigidos

### 1. Gerador do professor — `random_noise()` (previsto em G0)
- **Sintoma (confirmado):** `ValueError: too many values to unpack (expected 5)` em
  `build()` ao rodar `--level intermediate` ou `--level challenge` quando o cenário
  aleatório é sorteado (ex.: `--level challenge --seed 5`).
- **Causa:** `random_noise()` chamava `scenario_normal(start)`, que devolve um dict
  **já construído** por `build()` (processos/permissões são dicts, logs são pares
  `(datetime, msg)`), e reenviava esses dados a `build()`, que espera tuplas cruas.
- **Correção:** extraí os dados crus do cenário normal para o helper `_normal_raw()`;
  `scenario_normal()` e `random_noise()` passaram a partir dele. Nenhum dado de
  cenário foi alterado — apenas a origem (tuplas cruas em vez do dict construído).

### 2. `nonroot_writable` comparava `mtime` com fuso vs. sem fuso
- **Sintoma (encontrado no desenvolvimento):** `TypeError: can't compare
  offset-naive and offset-aware datetimes` ao ordenar a timeline.
- **Causa:** `FileInfo.mtime` vinha do CSV com `-03:00`, enquanto os horários do
  journal são wall-clock sem fuso. O plano manda **comparar em wall-clock naive**.
- **Correção:** `mtime` é normalizado para wall-clock naive em `normalize._build_files`
  (via `collect_dataset.to_naive_iso`), coerente com a regra de quirks do §2.

### 3. Campos `sockets`/`cron` não chegavam ao `Snapshot` (bug próprio, corrigido)
- **Causa:** o contêiner cru `RawDataset` não tinha os campos `sockets`/`cron`, então
  os extras coletados no live eram descartados silenciosamente.
- **Correção:** campos adicionados a `RawDataset`; o coletor live agora os repassa.

### 4. Índices de coluna do `ss` (bug próprio, corrigido)
- **Causa:** `Local`/`Peer` estavam lidos como colunas 3/4; em `ss -H` são 4/5.
- **Correção:** índices ajustados; `local`, `peer`, `process` e `pid` saem corretos.

## Detalhes de implementação (não são desvios de comportamento)

- **`RawDataset` como estrutura intermediária.** O plano fala em "registros crus →
  Snapshot"; materializei esses registros no dataclass `RawDataset` (em
  `collect_dataset.py`), compartilhado pelos dois coletores. É o "raw records" do G2/G3.
- **`Snapshot.to_dict()`** foi adicionado para serializar em JSON (chaves de PID viram
  string). É utilitário de saída; não altera o contrato de campos.
- **Docstrings de campos do `model.py`.** Cada campo tem um comentário de uma linha
  descrevendo-o, além do docstring de classe (item 6 do checklist).
- **`--scenario` e `metadata.json`.** Com `--scenario`, o campo `scenario` do
  `metadata.json` reflete o cenário corretamente; o campo `level` permanece no
  padrão (`basic`) por ser irrelevante nesse modo. Sem impacto na coleta.

## Pendências / não feito neste ambiente

- **`lab/setup_lab.sh` / `lab/teardown_lab.sh`:** escritos e validados com `bash -n`
  (sintaxe OK), mas **não executados**, porque exigem root na **VM Kali** e criam
  unidades systemd, binário SUID e um servidor HTTP — fora do escopo desta máquina.
  Devem ser testados na VM (checklist item 5).
- **`sudo python3 -m investigator --live`:** o modo live foi validado **sem** root
  nesta máquina (roda e lista lacunas corretamente, 200+ processos mapeados por
  cgroup, sockets e cron coletados). A execução **com** `sudo` deve ser feita na VM
  (checklist item 3), pois aqui o sudo é interativo/indisponível.

## Verificação executada

- `python3 generate_dataset.py --level intermediate --batch 5` — sem crash.
- `--scenario` para os 9 cenários nomeados + `random` — todos geram.
- `python3 -m investigator --dataset training/<cenário> --dump-snapshot` para os 9
  cenários — `snapshot.json` válido, com `ancestry` e `timeline` preenchidos.
- `python3 -m investigator --live --dump-snapshot` (sem sudo) — roda e lista lacunas.
- `python3 -m unittest tests.test_normalize` — 30 testes, OK.
- Conferência manual: resultados esperados do §4 conferem no nível dos fatos do
  Snapshot (ex.: `correlation` → backup.sh 0777 gravável por não-root;
  `writable_parent_dir` → razão de diretório-pai; `tampered_after_login` → mtime
  posterior ao login e reinício posterior; `user_to_root` → root descende de sessão
  aluno; `missing_evidence` → `/opt/x/run.sh` ausente de `permissions.csv`).
