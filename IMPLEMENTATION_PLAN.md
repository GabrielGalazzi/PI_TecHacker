# Endpoint Investigator — Implementation Plan

## Context

The assignment (`AI - Tecnologias Hackers 26-2.pdf`) asks for a tool that collects, relates and interprets the state of a GNU/Linux endpoint. It must cover **processes, permissions and services**, implement **at least two correlations**, and separate **evidência / interpretação / hipótese / evidência ausente**. It must also say plainly when the evidence is not enough for a conclusion. The presentation is on **6 Oct**.

The repo currently has only the PDF, an empty `README.md` and the professor's `generate_dataset.py`.

The work is split **linearly** along the pipeline in the PDF:

```
COLETA → NORMALIZAÇÃO  ║  CORRELAÇÃO → EVIDÊNCIAS → HIPÓTESES → RESULTADO
      Galazzi          ║                  Sardou
   (30/09 – 02/10)  HANDOFF              (03/10 – 05/10)
```

- **Galazzi** works alone first. They build everything needed to *observe* the endpoint and structure it into one normalized `Snapshot`. That includes both collectors, the identity and permission logic, process ancestry chains, the event timeline, the test data and the Kali lab. They finish by handing over a checklist-verified package.
- **Sardou** picks up the finished `Snapshot` and works alone to *reason* about it: correlations, findings, report, CLI wiring, acceptance tests, live integration, and final assembly of the docs.
- Each member presents the half they built.

Guiding principle: a small, deterministic, explainable tool. It does not try to find as many "vulnerabilities" as possible. It shows *why* each conclusion was reached, and when no conclusion can be reached.

---

## Workload balance (≈ 24 h each)

The hour figures are rough estimates for comparing the two halves, not deadlines.

| Galazzi | h | Sardou | h |
|---|---|---|---|
| G0 Setup, generator bug fix, `--scenario` | 1.5 | Verify the handoff | 0.5 |
| G1 `model.py` (Snapshot side) | 1 | S1 Finding model | 0.5 |
| G2 Dataset collector (4 parsers + quirks) | 2 | C1 service × permission | 2.5 |
| G3 Normalization: paths, mode flags, `nonroot_writable`, process↔service mapping, log linking | 4 | C2 execution context | 2 |
| G3b Process ancestry chains + structured timeline | 2.5 | C3 file × user privilege | 2 |
| G4 Minimal CLI + `--dump-snapshot` | 1 | C4 temporal reconstruction | 2 |
| G5 Live collector (/proc, systemctl, stat, journalctl, ss, cron) | 5 | Scoring and conclusions | 1 |
| G6 4 new scenarios + lab scripts + `test_normalize.py` | 5.5 | S3 Report (terminal, md, json) | 3 |
| G7 Docs: 5 README sections + 3 technical-doc sections | 2 | S4 CLI wiring, exit codes, acceptance tests | 2.5 |
| | | S5 Live integration on Kali + **bug-fix buffer** | 4 |
| | | S5 Docs: 3 README sections + 4 technical-doc sections + PDF export + `demo.md` | 4 |
| **Total** | **24.5** | **Total** | **24** |

How the two halves differ in kind:
- Galazzi writes more code: operating-system interfaces and parsers.
- Sardou does more reasoning and writing: rules, finding texts, documentation.

Sardou's half includes a 2 h buffer, because it ends the day before the presentation and absorbs any integration bugs.

Primary grading responsibility is also even:

| Galazzi | Sardou | Shared |
|---|---|---|
| Processos/permissões/serviços (2.0) + Arquitetura/código (1.0) = **3.0** | Correlação (2.0) + Evidência/hipótese (1.5) = **3.5** | Funcionamento (3.0), Demo (0.5) |

---

## 1. Solution at a glance

| Decision | Choice | Why |
|---|---|---|
| Language | Python 3.10+, **standard library only** | Kali ships Python; nothing to install; the generator is already Python |
| Execution | On demand, one snapshot (no agent) | The PDF allows it explicitly; simpler |
| Automation | **Fully automatic once started.** One command runs collect → normalize → correlate → report with no prompts or manual steps. People only (1) start it (with `sudo` in live mode) and (2) read the report | The PDF describes the tool as helping an analyst. Its output is hypotheses to review, not verdicts |
| Inputs | `--dataset DIR` (professor's format) **and** `--live` (Kali VM) | Demo works on the provided datasets and on a controlled VM |
| Output | Terminal report + `report.md` + `report.json` | Readable for the demo; structured for grading |
| LLM inside the tool | **None** | All analysis is rule-based and traceable, which avoids the "DADOS → LLM" anti-pattern. AI use during development is documented in the technical doc |
| Tool output language | Portuguese (labels: Evidência, Interpretação, Hipótese, Evidência ausente) | Matches the evaluation vocabulary |

### Repository layout (owner of each file)

```
investigator/
  __main__.py         CLI: --dataset | --live, --out, --dump-snapshot    Galazzi creates → Sardou extends
  model.py            Snapshot side: Process, Service, FileInfo, LogEvent, TimelineEvent, Snapshot   Galazzi
                      Finding side:  Evidence, Finding (appended)                                    Sardou
  collect_dataset.py  processes.csv, permissions.csv, services.txt, journal.log       Galazzi
  collect_live.py     /proc, systemctl show, os.stat, journalctl, ss, cron            Galazzi
  normalize.py        raw records → Snapshot + derived facts, mappings, ancestry, timeline   Galazzi
  correlate.py        correlations C1–C4 → Findings                                   Sardou
  report.py           terminal / Markdown / JSON rendering                            Sardou
lab/setup_lab.sh, lab/teardown_lab.sh                                                 Galazzi
tests/test_normalize.py (Galazzi)   tests/test_scenarios.py (Sardou)
generate_dataset.py   fixed + extended                                                Galazzi
README.md, docs/documento_tecnico.md (→ PDF, ≤ 4 pages)   each writes their own sections (§6)
.gitignore            training/, reports/, __pycache__/                               Galazzi
```

Final usage:
```
python3 -m investigator --dataset training/correlation --out reports/correlation
sudo python3 -m investigator --live --out reports/live
```

---

## 2. PART 1 — Galazzi: Coleta & Normalização (30/09 → 02/10)

**Goal of this half:** any input, whether a dataset or the live machine, becomes the same structured `Snapshot`, with process chains and a timeline already built. Every fact records where it came from, and everything that could not be collected is listed.

### G0. Setup
- Commit the PDF and `generate_dataset.py`. Add `.gitignore` and the package skeleton.
- **Fix the existing generator bug:** `random_noise()` passes already-built dicts back into `build()` and crashes with `ValueError: too many values to unpack`. This breaks `--level intermediate` and `--level challenge` whenever that scenario is chosen (verified).
- Add `--scenario NAME` to the generator for deterministic output.

### G1. The contract: `investigator/model.py` (Snapshot side)

```python
Process:  pid, ppid, user, uid|None, euid|None, state, cmdline, exe|None,
          script|None        # script argument when exe is an interpreter (bash, sh, python3, perl…)
          start|None, unit|None, unit_method|None,   # cgroup|mainpid|execstart|script|ancestor|name
          ancestry[list[int]],                       # PIDs from parent up to PID 1
          src                # provenance, e.g. "processes.csv:5" or "/proc/2417/status"
Service:  unit, active, user, exec_start, main_pid|None, unit_file|None, paths[list], src
FileInfo: path, type, owner, group, mode(int), mtime|None,
          world_writable, group_writable, suid, sgid,
          nonroot_writable: bool|None, nonroot_reason: str,   # "others:w", "owner=aluno", "dir /opt/x 0777"
          src
LogEvent: ts, ident, pid|None, unit|None, message, src
TimelineEvent: ts, kind,    # service_start|service_stop|login|session|process_start|file_mtime
          subject,          # unit / user / pid / path
          detail,           # e.g. {"user": "aluno", "ip": "10.20.30.44", "method": "publickey"}
          src
Snapshot: source("dataset"|"live"), host, taken_at, ran_as_root,
          processes{pid:Process}, services{unit:Service}, files{path:FileInfo},
          logs[LogEvent], timeline[TimelineEvent] (sorted),
          sockets[dict], cron[dict],      # extras; may be empty
          gaps[str]                       # what could NOT be collected
```
Give every field a one-line docstring. This is what Sardou reads first.

### G2. Dataset collector (`collect_dataset.py`)
- `processes.csv` (timestamp,pid,ppid,user,stat,cmd) and `permissions.csv` (path,type,owner,group,mode,mtime): use `csv.DictReader`. Keep the line number in `src`.
- `services.txt`: skip the header, then `line.split(maxsplit=3)` → unit, active, user, execstart. Do **not** rely on fixed widths, because long unit names break them.
- `journal.log`: parse `^(\w{3} \d{2} \d{2}:\d{2}:\d{2}) (\S+) ([^\[:]+)(?:\[(\d+)\])?: (.*)$`.
- Dataset quirks to handle and document:
  - `journal.log` has no year. Take it from `processes.csv` or `metadata.json`.
  - The generator appends `-03:00` to UTC wall-clock times in the CSVs, while the journal carries the same wall-clock without an offset. Compare **naive wall-clock** times.
  - The `timestamp` column in `processes.csv` is the observation time of each row, not the process start time.

### G3. Normalization (`normalize.py`)
- **Path extraction** from cmdline or ExecStart: strip systemd prefixes (`-@:+!`). The executable is argv[0]. If argv[0] is an interpreter, the first absolute-path argument is `script`.
- **Mode flags:** world-writable, group-writable, SUID and SGID, from `int(mode, 8)`.
- **`nonroot_writable` and its reason** (the core permission concept). The file counts as writable by a non-root user when any of these holds:
  - others have write (`o+w`);
  - the group has write and the group is not `root`. In live mode, check the group's members via `grp`/`pwd`. In a dataset, assume the group may contain unprivileged users and state that in the reason;
  - the owner is not root, because the owner can always rewrite or `chmod` the file;
  - **any parent directory** satisfies one of the above, because the file can then be replaced.

  Use `None` when no permission data exists.
- **Process → service mapping**, trying these methods in order and recording which one matched:
  1. cgroup (live)
  2. MainPID (live)
  3. exact `cmd == ExecStart` with ppid 1
  4. same script path
  5. inherited from a mapped ancestor
  6. unit base name equals the exe basename (weak; covers `apache2.service` → `/usr/sbin/apache2`)
- **Log → process/service linking:** by PID, by `_SYSTEMD_UNIT`, by ident equal to the unit base name (`backup-agent[2417]`), and by `systemd[1]: Started X.service`.

### G3b. Ancestry and timeline (the structured inputs for C2 and C4)
- **`Process.ancestry`:** walk the PPIDs up to PID 1. Guard against cycles and against parents missing from the snapshot. A missing parent is recorded in `gaps`, e.g. "PPID 900 de PID 1234 ausente do snapshot".
- **`Snapshot.timeline`:** convert log lines and metadata into typed events, sorted by time:
  - `Accepted (\w+) for (\S+) from (\S+)` → `login` (user, ip, method)
  - `New session \d+ of user (\S+)` → `session`
  - `Started|Starting X.service` → `service_start`
  - `X.service: Deactivated|Stopped` → `service_stop`
  - live process start times → `process_start`
  - `mtime` of every file in `files` → `file_mtime`

### G4. Minimal CLI (`__main__.py`)
- `--dataset DIR | --live`, `--out DIR`, and `--dump-snapshot`, which writes `snapshot.json` (the normalized Snapshot) and prints a count summary.
- This is what Galazzi's half outputs. It lets Sardou inspect exactly what they receive.

### G5. Live collector (`collect_live.py`, run with `sudo` on Kali)
- **Processes:** for each `/proc/[0-9]*`, read:
  - `status`: Name, State, PPid, and `Uid:`/`Gid:` (real, effective, saved, fs).
  - `cmdline`: NUL-separated.
  - `readlink exe`.
  - `cgroup`: gives `…/system.slice/<unit>.service`.
  - `stat` field 22 plus `btime` from `/proc/stat` and `SC_CLK_TCK`: gives the start time.
  - Skip kernel threads (empty cmdline).
  - Any `PermissionError` is appended to `gaps`.
- **Services:** list running units with `systemctl list-units --type=service --state=running --no-legend --plain`. Then run one call of `systemctl show <units…> -p Id,ActiveState,User,Group,MainPID,ExecStart,FragmentPath,ActiveEnterTimestamp`. Blocks are separated by blank lines, and `ExecStart` has the form `{ path=… ; argv[]=… ; … }`, so parse the `argv[]=` part.
- **Files, collected by context and not by a filesystem sweep:** stat only these paths, each with every parent directory up to `/`, via `os.lstat` and `pwd`/`grp`:
  - executables and scripts referenced by running services;
  - unit files (`FragmentPath`);
  - process executables and interpreter scripts;
  - paths referenced in cron.
- **Logs:** `journalctl -o json --since -24h -n 5000 --no-pager`. Keep `__REALTIME_TIMESTAMP`, `_PID`, `_SYSTEMD_UNIT`, `SYSLOG_IDENTIFIER`, `MESSAGE`. If that fails, record a gap.
- **Extras (add them only if the core is done by midday 02/10):**
  - `ss -tulpnH` and `ss -tupnH state established`: parse `users:(("name",pid=N,fd=M))` to map sockets to PIDs.
  - `/etc/crontab` and `/etc/cron.d/*`: persistence entries, with user and absolute paths.
- If the tool does not run as root, it says so in `gaps`, because visibility is partial.

### G6. Test data, lab and tests
- **Add 4 generator scenarios**, each exercising one correlation path Sardou will build:
  - `tampered_after_login`: root service, script 0777, script mtime *after* a non-root SSH login, and the service restarts after that.
  - `writable_parent_dir`: script 0755 root, but its directory is 0777.
  - `user_to_root`: `sshd: aluno → bash (aluno) → bash (root)` with no sudo/su in the chain.
  - `missing_evidence`: a root service references `/opt/x/run.sh`, which is absent from `permissions.csv`.
- **`lab/setup_lab.sh`** (Kali VM only, run as root), plus `lab/teardown_lab.sh` that removes everything it creates:
  - `ei-lab-backup.service` (User=root) runs `/opt/ei-lab/backup.sh` (a sleep loop) with mode **0777**. This is the positive case.
  - `ei-lab-safe.service` (root) runs `/opt/ei-lab-safe/agent.sh` with mode **0700**. This is the control case and must *not* be flagged.
  - `/usr/local/bin/ei-lab-id` is a copy of `/usr/bin/id` with mode 4755 (non-standard SUID).
  - As user `kali`, `python3 -m http.server 8081` runs from `/tmp/ei-lab/` (a listening port with no service).
- `tests/test_normalize.py` covers:
  - ExecStart/argv parsing;
  - mode flags;
  - `nonroot_writable`, including the parent-directory case;
  - ancestry, including a missing parent;
  - login and service events in the timeline;
  - the services.txt and journal parsers.

### G7. Docs for this half (written in full before the handoff)
- README sections: **Arquitetura, Dependências, Instalação, Execução, Fontes de informação** (with the man-page references from §10).
- Technical doc sections: **Problema, Arquitetura, Decisões técnicas**, plus the collection-side limitations (single snapshot, dataset gaps, need for root).

### ✅ HANDOFF checklist (end of 02/10). Galazzi ticks each item and Sardou verifies it.
1. `python3 generate_dataset.py --scenario X --output training/X` works for all 5 original scenarios, `random`, and the 4 new ones. `--level intermediate --batch 5` no longer crashes.
2. `python3 -m investigator --dataset training/X --dump-snapshot` produces a correct `snapshot.json` for every scenario, **including `ancestry` and `timeline`**.
3. `sudo python3 -m investigator --live --dump-snapshot` works on the Kali VM with the lab running. Without `sudo` it still runs and lists gaps.
4. `python3 -m unittest tests.test_normalize` passes.
5. `lab/setup_lab.sh` and `lab/teardown_lab.sh` have been tested on the VM.
6. The Snapshot fields of `model.py` have docstrings.
7. Galazzi's README and technical-doc sections are written.
8. A **"Handoff notes"** section has been appended to this file: deviations from the plan, known quirks, and anything not done.

---

## 3. PART 2 — Sardou: Correlação, Evidências & Resultado (03/10 → 05/10)

**Starting point:** a tested `Snapshot` for every dataset and for the live VM, with ancestry chains, a timeline and gaps already built, plus the expected results in §4.

**Goal of this half:** turn the Snapshot into findings that separate what was observed, what it means and what it might explain, and state what is still missing.

### S1. Finding model (append to `model.py`)
```python
Evidence: text, src
Finding:  id, title, correlation("C1".."C4"), severity(alta|média|baixa|info),
          confidence(alta|média|baixa), conclusion(RISCO|CONFIG_INADEQUADA|INCONCLUSIVO|CONTEXTO_OK),
          chain[str], evidence[Evidence], interpretation, hypothesis, missing[str]
```

### S2. Correlations (`correlate.py`)

All four correlations listed in the PDF are implemented. The minimum is 2, so build C1 and C2 first.

**C1. Processo + Serviço + Permissão → hipótese de risco (privileged service × modifiable resource)**
- For each active service running as root (User empty or `root`), look at every referenced path: the binary, the script and the unit file. Use the mapped processes as supporting evidence.
- `nonroot_writable == True` → **RISCO / alta**. The chain looks like: `serviço → root → PID → script → modo 0777 → gravável por não-root`.
- The path is non-standard (`/opt`, `/usr/local`, `/home`, `/srv`, `/tmp`, `/var`) and has no permission data → **INCONCLUSIVO**, with missing evidence "permissões de X".
- A standard system binary (`/usr/sbin`, `/usr/bin`, `/sbin`, `/bin`) with no permission data is listed once under "não avaliado". It is not a finding, to avoid noise.
- Everything is root-only → **CONTEXTO_OK**, listed under "Verificações sem achado". This shows that "serviço root" alone is never flagged.
- Missing evidence: script content or hash against a baseline; who modified the file (auditd); whether the service restarted after the last `mtime`.

**C2. Processo + PPID + usuário → contexto de execução** (uses `Process.ancestry`)
- Render the chain, e.g. `init(1,root) → sshd(612,root) → sshd: aluno(2630,aluno) → bash(2638,aluno)`.
- A root process descends from a non-root session with no sudo/su/pkexec or SUID binary in the chain → **RISCO / alta**.
- A root process runs an exe or script from a user-writable location (`/tmp`, `/dev/shm`, `/var/tmp`, `/home`) → **RISCO / alta**. The same case under the same non-root user → CONTEXTO_OK.
- A child of a root service makes an outbound call (a URL or IP in argv, or an established socket in live mode) → **INCONCLUSIVO / info**. If the service's own logs describe that activity, say so. This is the ambiguous scenario: it is *not* concluded to be C2 or malware.
- (live) A listening socket belongs to a process with no service mapping → **INCONCLUSIVO / média**.
- (live) Real UID ≠ effective UID gets a note: SUID execution context.
- A binary name (`curl`, `bash`) is **only context**. It never triggers a finding without parent, user or service evidence (see PDF "ATENÇÃO").

**C3. Serviço + arquivo + usuário → relação de privilégio (files not already covered by C1)**
- SUID or SGID root binary outside the standard directories → **INCONCLUSIVO / média**. Note whether any process or service uses it. If it is also non-root-writable → **RISCO / alta**.
- World-writable file not referenced by any service, process or cron entry → **CONFIG_INADEQUADA / baixa**. Missing evidence: crontabs and timers (datasets do not include them; live mode checks cron).
- Sensitive files (`/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, unit files) with unsafe modes → **RISCO / alta**. `/etc/shadow 0640 root:shadow` → CONTEXTO_OK.

**C4. Processo + serviço + log → reconstrução temporal** (uses `Snapshot.timeline`)
- It enriches C1 and C3 findings:
  - If a non-root `login` event exists, add it as evidence.
  - If the file's `file_mtime` is **after** that login, raise the confidence and state "modificação posterior ao login de X".
  - If the `mtime` is before the login, state "sem indício de modificação durante a sessão observada".
  - If a `service_start` comes after the modification, the modified script may already have run. Add that to the hypothesis.
- It also produces standalone findings for state inconsistencies, such as a `service_stop` while the snapshot shows the process running, or a log PID missing from the snapshot. These are **INCONCLUSIVO / info**: "possível reinício, reutilização de PID ou log rotacionado".

**Scoring (kept simple and explainable):**
- Severity is the impact if the hypothesis is true.
- Confidence is the number of *independent source types* in the evidence (services, processes, permissions, logs, /proc, sockets): 1 → baixa, 2 → média, ≥3 → alta.
- A RISCO or INCONCLUSIVO finding needs evidence from ≥2 sources. Single-source findings may only be CONFIG_INADEQUADA.

### S3. Report (`report.py`), terminal plus `report.md` plus `report.json`

Sections:
1. Header: source, host, time, whether it ran as root.
2. Summary: counts, and findings per conclusion.
3. **Achados**, sorted by severity.
4. **Verificações sem achado**, the CONTEXTO_OK list.
5. **Linha do tempo**, rendered from `Snapshot.timeline`.
6. **Lacunas de coleta / limitações desta execução**, taken from `Snapshot.gaps`.

Example finding (correlation scenario, illustrative):
```
[ALTA] F-001 Serviço root executa script gravável por qualquer usuário        (C1)
Cadeia: backup-agent.service → User=root → PID 2417 → /opt/backup/backup.sh → 0777
EVIDÊNCIA (observado)
  - services.txt:4     backup-agent.service running user=root exec="/bin/bash /opt/backup/backup.sh"
  - processes.csv:5    pid=2417 ppid=1 user=root cmd="/bin/bash /opt/backup/backup.sh"
  - permissions.csv:3  /opt/backup/backup.sh file root:root 0777
  - journal.log:6      sshd[2630]: Accepted publickey for aluno from 10.20.30.44
INTERPRETAÇÃO  Script executado como root pode ser alterado por qualquer usuário local (bit o+w).
HIPÓTESE       Um usuário não privilegiado (ex.: aluno, com sessão ativa) poderia inserir comandos
               executados como root na próxima execução. Isso NÃO prova exploração.
EVIDÊNCIA AUSENTE
  - conteúdo/hash do script vs. versão conhecida
  - autor da última modificação (auditd); mtime é anterior ao login observado
  - reinícios do serviço após a modificação
CONCLUSÃO: RISCO (configuração insegura, exploração não comprovada) — confiança alta (4 fontes)
```

### S4. CLI wiring and acceptance tests
- Extend `__main__.py` so the default run is collect → normalize → correlate → report. Keep `--dump-snapshot`.
  - It never asks for input.
  - Exit code: 0 = no RISCO, 1 = at least one RISCO, 2 = execution error. Scripts or cron can use it if someone later wants scheduled runs.
  - Scheduled runs are out of scope, as the PDF allows.
- `tests/test_scenarios.py` (unittest): for each scenario, generate it with `--scenario` into a temporary directory, run the pipeline and assert the expected conclusions in §4.

### S5. Live integration and final docs
- On the Kali VM: run `setup_lab.sh`, then `--live`, check the results against the last row of §4, fix any false positives, then run `teardown_lab.sh`. The remaining time is the bug-fix buffer.
- README sections: **Correlações implementadas, Formato de saída, Limitações** (analysis side).
- Technical doc sections: **Estratégia de investigação, Principais correlações, Uso de IA, Limitações** (analysis side). Then join them with Galazzi's sections and export to PDF (≤4 pages).
- Write `docs/demo.md` with the exact demo commands for 06/10.

---

## 4. Expected results per scenario (Galazzi builds the data, Sardou's acceptance target)

| Scenario | Expected output |
|---|---|
| `normal` | No RISCO. CONTEXTO_OK for ssh/cron and for `/etc/shadow`. apache2 is mapped by name (weak); dropping to www-data is expected context |
| `permission` | CONFIG_INADEQUADA/baixa: `/opt/reports/report.sh` 0777 with no link to privileged execution. Missing: crontabs |
| `privileged_service` | C1 CONTEXTO_OK (backup.sh 0700 root). C2 INCONCLUSIVO: root service → curl to `updates.example.invalid`, consistent with the service log. C4 INCONCLUSIVO: log says "Deactivated" but the snapshot shows it running |
| `correlation` | **C1 RISCO/alta**: backup-agent root + backup.sh 0777. C4 adds aluno's login, after the mtime. C3 INCONCLUSIVO/média: `/usr/local/bin/report-sync` SUID 4755, non-standard and unused |
| `ambiguous` | C1 CONTEXTO_OK (agent.py 0755 root). C2 INCONCLUSIVO: outbound push to `metrics.example.invalid`, logs consistent with monitoring; explicitly "não concluir C2" |
| `random` (fixed) | 0777 → RISCO. 0770 root:root, 0750 or 0700 → CONTEXTO_OK |
| `tampered_after_login` | RISCO/alta with **high confidence**: mtime after a non-root login, and the service restarted afterwards |
| `writable_parent_dir` | RISCO/alta through the directory reason |
| `user_to_root` | C2 RISCO/alta: root shell descends from a user session with no sudo |
| `missing_evidence` | INCONCLUSIVO: script permissions not collected |
| Kali lab (live) | `ei-lab-backup` RISCO; `ei-lab-safe` CONTEXTO_OK; `ei-lab-id` SUID INCONCLUSIVO; `:8081` listener with no service INCONCLUSIVO |

---

## 5. Schedule (today is 30 Sep; presentation is 6 Oct). Three working days each

| Day | Who | Work | ≈h |
|---|---|---|---|
| Wed 30/09 | Galazzi | G0 setup and generator fix; G1 `model.py`; G2 dataset collector; start G3 | 6.5 |
| Thu 01/10 | Galazzi | Finish G3; G3b ancestry and timeline; G4 `--dump-snapshot`; 4 new scenarios; `test_normalize.py` | 9 |
| Fri 02/10 | Galazzi | G5 live collector (core first, extras if time); lab scripts; G7 docs; **HANDOFF checklist** | 9 |
| Sat 03/10 | Sardou | Verify the handoff; S1; C1 and C2; terminal report | 7 |
| Sun 04/10 | Sardou | C3 and C4; scoring; `report.md`/`report.json`; exit codes; `test_scenarios.py` | 9 |
| Mon 05/10 | Sardou | S5 live integration and bug-fix buffer; docs; PDF export; `docs/demo.md` | 8 |
| Mon 05/10 evening | Both | One run-through of the presentation (§8) | 1 |
| Tue 06/10 | Both | Present | — |

**If Galazzi runs late:** the dataset path (G0–G4) is required and must be handed over on time. The live extras (ss, cron) can be dropped and recorded in the Handoff notes. The PDF accepts a demo on "ambiente **ou** dataset de teste".

Git: Galazzi works on `coleta` and merges into `main` at the handoff. Sardou branches `analise` from that `main`.

---

## 6. Deliverables mapped to the evaluation criteria

| Criterion (points) | How it is met | Owner |
|---|---|---|
| Funcionamento (3.0) | Both modes run end to end; acceptance tests pass on all scenarios; live lab demo | Shared |
| Processos, permissões, serviços (2.0) | /proc identity (real/effective UID), PPID ancestry, contextual stat with parent directories, systemd unit properties, process↔service mapping | Galazzi |
| Correlação (2.0) | C1–C4, with the chain shown in every finding | Sardou |
| Evidência vs interpretação vs hipótese (1.5) | Fixed four-part finding format with `src` provenance, CONTEXTO_OK and INCONCLUSIVO outcomes, and gaps | Sardou |
| Arquitetura, código, documentação (1.0) | One module per pipeline stage; stdlib only; README; technical doc of ≤4 pages | Galazzi (architecture) + both (docs) |
| Demonstração e domínio (0.5) | Each member presents the half they built | Shared |

**README.md** sections:

| Galazzi | Sardou |
|---|---|
| Arquitetura, Dependências (Python 3.10+; `systemctl`, `journalctl` and `ss` for live mode), Instalação, Execução, Fontes de informação | Correlações implementadas, Formato de saída, Limitações |

**docs/documento_tecnico.md** (export to PDF, ≤4 pages):

| Galazzi | Sardou |
|---|---|
| Problema, Arquitetura, Decisões técnicas, collection limitations | Estratégia de investigação, Principais correlações, Uso de IA, analysis limitations; final assembly |

For AI use, state honestly that AI was used for planning and coding support, and that the tool itself does not use an LLM.

---

## 7. Limitations to document (the tool must say them, not hide them)

Collection side (Galazzi):
- **Single snapshot:** short-lived processes are not seen; logs may have been rotated or cleared; `mtime` can be forged (`touch`).
- **Dataset mode:**
  - No UIDs or group membership.
  - No crontabs or timers.
  - Timestamps have no year and the timezone is ambiguous.
  - Process↔service mapping relies on command matching.
- **Live mode:** it needs root for full visibility, and each missing permission is reported as a gap.

Analysis side (Sardou):
- **False positives:** group-writable files are assumed writable by non-root in dataset mode.
- **False negatives:** a world-writable file may be executed by cron or timers, which datasets do not include.
- **Heuristics:** binary names and paths are used only as context.
- **Out of scope:**
  - package integrity (`dpkg --verify`) and hashes;
  - POSIX ACLs and file capabilities (`getcap`);
  - SELinux/AppArmor;
  - containers and namespaces;
  - kernel-level rootkits (the tool trusts `/proc`).
- **No attribution:** findings describe *conditions* that enable abuse. They never prove exploitation.

---

## 8. Presentation (same order as the pipeline, ≈ equal time)

1. **Galazzi (first half):** the problem, then the architecture and pipeline, then how each dimension is observed (processes and ancestry via /proc, services via systemd, contextual permissions and `nonroot_writable`, the timeline). Show `setup_lab.sh` and `--dump-snapshot`, i.e. what the tool "sees".
2. **Sardou (second half):** the correlations C1–C4, then the full run on the `correlation` dataset (evidence → interpretation → hypothesis → missing evidence), then `ambiguous` and `privileged_service` (INCONCLUSIVO and CONTEXTO_OK), then `sudo ... --live` on the lab, then the limitations.
3. Both: Q&A. Each member should be able to explain the other's half at a high level.

---

## 9. Verification

```
# Galazzi's handoff
python3 generate_dataset.py --level intermediate --batch 5 --output training/   # no crash after the fix
for s in normal permission privileged_service correlation ambiguous \
         tampered_after_login writable_parent_dir user_to_root missing_evidence; do
  python3 generate_dataset.py --scenario $s --output training/$s
  python3 -m investigator --dataset training/$s --dump-snapshot --out reports/$s
done
python3 -m unittest tests.test_normalize

# Sardou's final check
python3 -m unittest discover tests          # all acceptance assertions from §4 pass
python3 -m investigator --dataset training/correlation < /dev/null; echo $?   # no prompts; exit code 1 (RISCO)
# On the Kali VM:
sudo bash lab/setup_lab.sh && sudo python3 -m investigator --live --out reports/live
python3 -m investigator --live               # without sudo: must run and list gaps, not crash
sudo bash lab/teardown_lab.sh
```
Check by hand: every finding has all four parts and at least one `src` per evidence line; `ei-lab-safe` is not flagged; `report.json` is valid JSON.

---

## 10. Ground rules and references

- Write all code yourselves from the documentation. Do not paste code from websites or other groups.
- References (cite in the README under information sources):
  - `proc_pid_status(5)`: Uid/Gid are real, effective, saved and fs IDs; PPid.
  - `proc(5)`.
  - `systemctl(1)`: `show` is the machine-parsable interface; MainPID, ExecStart, FragmentPath.
  - `systemd.journal-fields(7)`: `_PID`, `_UID`, `_SYSTEMD_UNIT`, `_EXE`, `_CMDLINE`.
  - `ss(8)`.
  - `chmod(1)` / `inode(7)`: mode bits, SUID/SGID.

---

## Handoff notes (Galazzi fills this in on 02/10)

_Deviations from the plan, known quirks, and anything not done._

Relatório completo em `report_galazzi.md`. Resumo:

**Checklist de handoff**
1. ✅ `generate_dataset.py --level intermediate --batch 5` não quebra mais;
   `--scenario X` funciona para os 5 cenários originais, `random` e os 4 novos.
2. ✅ `python3 -m investigator --dataset training/X --dump-snapshot` gera
   `snapshot.json` correto para todos os cenários, com `ancestry` e `timeline`.
3. ⏳ `sudo python3 -m investigator --live` — validado **sem** root nesta máquina
   (roda e lista lacunas; mapeamento por cgroup, sockets e cron OK). A execução
   **com sudo** deve ser feita na VM Kali.
4. ✅ `python3 -m unittest tests.test_normalize` — 30 testes passam.
5. ⏳ `lab/setup_lab.sh` / `lab/teardown_lab.sh` — escritos e checados com `bash -n`;
   **pendente** de execução na VM Kali (exigem root e criam unidades/SUID/porta).
6. ✅ Campos do `Snapshot` documentados (comentário por campo + docstring de classe).
7. ✅ Seções de README e documento técnico de Galazzi escritas.
8. ✅ Esta seção de handoff preenchida.

**Correções de bug** (detalhes em `report_galazzi.md`):
- Gerador: `random_noise()` reaproveitava dict construído → `ValueError`. Corrigido
  via `_normal_raw()` (previsto em G0).
- `mtime` normalizado para wall-clock naive (regra de quirks do §2).
- `RawDataset` ganhou campos `sockets`/`cron`; índices de coluna do `ss` corrigidos.

**Quirks conhecidos / limitações da coleta** (também declaradas em `Snapshot.gaps`):
- Dataset: sem UID/EUID nem grupos; sem crontabs/timers; horários sem ano/fuso
  (tratados por wall-clock naive); mapeamento processo↔serviço por casamento de comando.
- Live: precisa de root para visão completa; cada leitura sem permissão vira lacuna.

**Interface para Sardou:**
- `collect_dataset.collect(dir) -> RawDataset` e `collect_live.collect() -> RawDataset`.
- `normalize.build_snapshot(raw) -> Snapshot` (o que Sardou consome).
- `Snapshot.to_dict()` serializa para JSON. `--dump-snapshot` grava `snapshot.json`.
- O `__main__.py` já tem o gancho do fluxo completo: importa `correlate`/`report`
  (ainda inexistentes) de forma tardia e, enquanto não existirem, cai no dump.
  Sardou deve prover `correlate.run(snap) -> findings` e
  `report.render(snap, findings, out_dir) -> int (exit code)`.
- O lado Finding (`Evidence`, `Finding`) está demarcado ao final de `model.py`.
