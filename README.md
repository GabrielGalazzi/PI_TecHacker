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

As quatro correlações do enunciado estão em `investigator/correlate.py`. Nenhuma
conclui a partir de um indicador isolado: cada regra cruza pelo menos duas fontes.

| | Fontes cruzadas | O que relaciona | Conclusões possíveis |
|---|---|---|---|
| **C1** | serviço + processo + permissão | Serviço ativo como root → processo que o executa → cada caminho referenciado (executável, script, unit file) → quem pode alterá-lo (`nonroot_writable`, inclusive por diretório-pai) | RISCO · INCONCLUSIVO (permissão não coletada) · CONTEXTO_OK (só root altera) · *não avaliado* (binário de sistema sem dados) |
| **C2** | processo + PPID + usuário | Cadeia de ancestralidade com a identidade de cada elo. Sinaliza processo root filho direto de processo não-root sem `sudo`/`su`/`pkexec`; processo root executando de `/tmp`, `/home`, `/dev/shm`, `/var/tmp`; filho de serviço root com destino externo em argv; e, no live, porta em escuta sem serviço dedicado e UID real ≠ efetivo | RISCO · INCONCLUSIVO · CONTEXTO_OK (elevação por `sudo`) |
| **C3** | arquivo + usuário + uso | Arquivos não explicados por C1: SUID/SGID fora dos diretórios padrão (e se alguém o usa), arquivo gravável por todos sem vínculo com execução privilegiada, arquivos de identidade (`/etc/shadow`, `/etc/sudoers`…) | INCONCLUSIVO · CONFIG_INADEQUADA · CONTEXTO_OK |
| **C4** | processo + serviço + log | Ordena no tempo login não-root, `mtime` do arquivo e (re)início do serviço, enriquecendo os achados de C1 (`C1+C4`). Também aponta log de desativação com o processo ainda em execução | enriquece C1 · INCONCLUSIVO |

Regras de pontuação, deliberadamente simples:

- **Severidade** é o impacto *se* a hipótese for verdadeira.
- **Confiança** é o número de tipos de fonte independentes na evidência
  (serviço, processo, permissão, log, socket): 1 = baixa, 2 = média, ≥ 3 = alta.
  Ela mede o quanto a *relação observada* está sustentada, não a hipótese.
- **RISCO exige ao menos duas fontes.** Com uma só, a conclusão é rebaixada para
  CONFIG_INADEQUADA ou INCONCLUSIVO, e a fonte que falta entra em "evidência ausente".
- Várias ocorrências com a **mesma causa** (ex.: um diretório gravável acima de
  vários serviços) viram um único achado.

O que nunca gera achado sozinho: serviço rodando como root, nome de binário
(`curl`, `bash`), conexão externa, bit SUID em diretório padrão.

## Formato de saída

Uma execução imprime o relatório no terminal e grava `report.md` e `report.json`
em `--out`. Todo achado tem as mesmas quatro partes, sempre separadas:

```
[ALTA] F-001 Serviço root backup-agent.service executa script gravável por não-root  (C1+C4)
Cadeia:        backup-agent.service → User=root → PID 2417 → /opt/backup/backup.sh (0777) → gravável por não-root [others:w]
EVIDÊNCIA (observado)
  - services.txt:4     backup-agent.service active=running user=root exec="/bin/bash /opt/backup/backup.sh"
  - processes.csv:5    pid=2417 ppid=1 user=root cmd="/bin/bash /opt/backup/backup.sh"
  - permissions.csv:3  /opt/backup/backup.sh file root:root 0777 mtime=2026-09-13T08:59:00
  - journal.log:6      login de aluno (publickey) a partir de 10.20.30.44 em 2026-09-14T09:25:00
INTERPRETAÇÃO  O script executado como root pode ser alterado por qualquer usuário local (bit o+w). […]
HIPÓTESE       Um usuário não privilegiado poderia inserir comandos […]. Isso NÃO prova exploração.
EVIDÊNCIA AUSENTE
  - conteúdo/hash de /opt/backup/backup.sh comparado a uma versão conhecida
  - autor da última modificação (auditd); o mtime pode ser forjado com touch
CONCLUSÃO:     RISCO (condição que permite abuso; exploração não comprovada) — relação observada com confiança alta (4 fontes)
```

Cada linha de evidência começa pela origem (`src`): a linha do arquivo do dataset
ou a interface do sistema consultada.

| Conclusão | Significado |
|---|---|
| `RISCO` | condição que permite abuso; exploração não comprovada |
| `CONFIG_INADEQUADA` | configuração inadequada, sem relação de privilégio demonstrada |
| `INCONCLUSIVO` | evidência insuficiente para concluir |
| `CONTEXTO_OK` | contexto verificado, sem achado |

Seções do relatório: cabeçalho e resumo · **Achados** · **Verificações sem achado**
(os `CONTEXTO_OK`) · **Não avaliado / observações** · **Linha do tempo** ·
**Lacunas de coleta** (de `Snapshot.gaps`).

Código de saída: `0` sem RISCO, `1` com ao menos um RISCO, `2` erro de execução.
A ferramenta não faz perguntas durante a execução.

## Limitações

Limitações da análise (as da coleta estão no documento técnico):

- **Achados são condições, não incidentes.** Nenhum achado atribui autoria nem
  prova exploração; coincidência temporal é descrita como coincidência.
- **Falsos positivos.** No modo dataset, arquivo com escrita de grupo é tratado
  como gravável por não-root (não há lista de membros). Um processo root filho de
  não-root pode vir de um mecanismo legítimo que o snapshot não mostra.
- **Falsos negativos.** Um arquivo gravável por todos pode ser executado por
  cron, timer ou unidade inativa que o dataset não traz — por isso sai como
  CONFIG_INADEQUADA, com essa ausência declarada. Processos efêmeros não aparecem.
- **Heurísticas.** O destino externo é lido de argv (URL ou IP); a relação entre
  log e atividade usa palavras-chave. Nomes de binário e caminhos são contexto.
- **`mtime` e logs podem ser forjados ou rotacionados**; a reconstrução temporal
  é tão boa quanto essas duas fontes.
- **Fora do escopo:** integridade de pacotes e hashes (`dpkg --verify`), ACLs
  POSIX e *capabilities* (`getcap`), SELinux/AppArmor, containers e namespaces,
  rootkits de kernel (a ferramenta confia em `/proc`).
