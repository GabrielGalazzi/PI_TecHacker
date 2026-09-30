# Endpoint Investigator

Ferramenta acadêmica que coleta, relaciona e interpreta o estado de um endpoint
GNU/Linux — **processos, permissões e serviços** — e produz hipóteses revisáveis,
separando **evidência**, **interpretação**, **hipótese** e **evidência ausente**.
Não é um scanner de vulnerabilidades: é uma ferramenta pequena, determinística e
explicável, que mostra *por que* cada conclusão foi alcançada e diz claramente
quando não há evidência suficiente para concluir.

> Dados de treinamento são sintéticos e fictícios; não representam incidentes reais.

---

## Arquitetura

O fluxo é linear, um módulo por etapa do pipeline:

```
COLETA ─────────────► NORMALIZAÇÃO ─────► CORRELAÇÃO ─► EVIDÊNCIAS ─► HIPÓTESES ─► RESULTADO
dataset/live            Snapshot único        C1–C4        (Evidence)    (Finding)     (report)
```

| Módulo | Papel |
|---|---|
| `investigator/model.py` | Contrato de dados: `Process`, `Service`, `FileInfo`, `LogEvent`, `TimelineEvent`, `Snapshot` (lado coleta) e `Evidence`/`Finding` (lado análise) |
| `investigator/collect_dataset.py` | Lê `processes.csv`, `permissions.csv`, `services.txt`, `journal.log` (formato do professor) |
| `investigator/collect_live.py` | Coleta ao vivo via `/proc`, `systemctl`, `os.lstat`, `journalctl`, `ss`, cron |
| `investigator/normalize.py` | Converte a coleta crua em um `Snapshot` com fatos derivados: caminhos, flags de modo, `nonroot_writable`, mapeamento processo↔serviço, ancestralidade e linha do tempo |
| `investigator/correlate.py` | Correlações C1–C4 → `Finding` (metade de análise) |
| `investigator/report.py` | Renderização em terminal, Markdown e JSON (metade de análise) |
| `investigator/__main__.py` | CLI: `--dataset` / `--live`, `--out`, `--dump-snapshot` |

**Ideia central:** qualquer entrada — um dataset ou a própria máquina — vira o
mesmo `Snapshot` normalizado, já com cadeias de processos e linha do tempo
construídas. Cada fato registra de onde veio (`src`), e tudo o que não pôde ser
coletado fica listado em `Snapshot.gaps`.

## Dependências

- **Python 3.10+**, **somente biblioteca padrão** (nada a instalar).
- Modo `--live` usa utilitários do sistema: `systemctl`, `journalctl` e `ss`
  (presentes em distribuições com systemd, como Kali). Cada utilitário ausente
  é registrado como lacuna em vez de interromper a execução.
- A coleta ao vivo completa requer privilégios de **root** (`sudo`); sem root a
  ferramenta ainda roda e declara a visibilidade parcial em `gaps`.

## Instalação

Não há instalação. Basta clonar o repositório e ter o Python 3.10+:

```bash
git clone <repo>
cd PI_TecHacker
python3 --version   # >= 3.10
```

## Execução

```bash
# A partir de um dataset (formato do professor)
python3 -m investigator --dataset training/correlation --out reports/correlation

# Coleta ao vivo na VM (visão completa com sudo)
sudo python3 -m investigator --live --out reports/live

# Apenas inspecionar o Snapshot normalizado (coleta + normalização)
python3 -m investigator --dataset training/correlation --dump-snapshot --out reports/correlation
```

Gerar datasets de teste:

```bash
# Um cenário nomeado e determinístico
python3 generate_dataset.py --scenario correlation --output training/correlation

# Por nível (aleatório dentro do nível)
python3 generate_dataset.py --level intermediate --batch 5 --output training/
```

Cenários disponíveis via `--scenario`: `normal`, `permission`,
`privileged_service`, `correlation`, `ambiguous`, `tampered_after_login`,
`writable_parent_dir`, `user_to_root`, `missing_evidence`, `random`.

Laboratório controlado (somente VM Kali, como root):

```bash
sudo bash lab/setup_lab.sh
sudo python3 -m investigator --live --out reports/live
sudo bash lab/teardown_lab.sh
```

Testes:

```bash
python3 -m unittest tests.test_normalize      # coleta/normalização (Galazzi)
python3 -m unittest discover tests            # suíte completa
```

## Fontes de informação

Toda a coleta foi escrita a partir da documentação oficial (man pages):

- `proc_pid_status(5)` — campos `Uid:`/`Gid:` (real, efetivo, salvo, fs) e `PPid`.
- `proc(5)` — layout de `/proc`, `stat` (campo 22 = starttime) e `/proc/stat` (`btime`).
- `systemctl(1)` — `systemctl show` como interface parseável por máquina
  (`MainPID`, `ExecStart`, `FragmentPath`, `ActiveEnterTimestamp`).
- `systemd.journal-fields(7)` — `_PID`, `_UID`, `_SYSTEMD_UNIT`, `_EXE`, `_CMDLINE`.
- `ss(8)` — sockets e mapeamento `users:(("nome",pid=N,fd=M))`.
- `chmod(1)` / `inode(7)` — bits de modo, SUID/SGID.

---

## Correlações implementadas

_(seção de Sardou — a ser preenchida na Parte 2)_

## Formato de saída

_(seção de Sardou — a ser preenchida na Parte 2)_

## Limitações

_(seção de Sardou — a ser preenchida na Parte 2; as limitações da coleta estão no documento técnico)_
