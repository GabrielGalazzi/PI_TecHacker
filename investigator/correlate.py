"""Correlação: Snapshot -> Findings.

Lê o ``Snapshot`` normalizado e relaciona fontes diferentes. Nenhuma regra
conclui a partir de um indicador isolado:

  * C1  processo + serviço + permissão  -> hipótese de risco
  * C2  processo + PPID + usuário       -> contexto de execução
  * C3  serviço + arquivo + usuário     -> relação de privilégio
  * C4  processo + serviço + log        -> reconstrução temporal

Cada ``Finding`` separa o que foi observado (``evidence``, sempre com ``src``)
do que é interpretação, do que é hipótese e do que falta para confirmá-la.

Regras de pontuação (simples e explicáveis):
  * severidade  = impacto SE a hipótese for verdadeira;
  * confiança   = nº de tipos de fonte independentes na evidência
                  (1 baixa, 2 média, >=3 alta);
  * RISCO exige evidência de pelo menos duas fontes; com uma só, a conclusão
    é rebaixada.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from .model import Evidence, FileInfo, Finding, Process, Service, Snapshot, TimelineEvent
from .normalize import USER_WRITABLE_DIRS, extract_paths

# Usuários que significam root em uma unidade (User= vazio é root no systemd).
_ROOT_SERVICE_USERS = {"", "root", "0"}

# Métodos de mapeamento processo->serviço fortes o bastante para dizer "este
# processo É o serviço". "ancestor" e "name" ficam de fora: sessões SSH herdam
# ssh.service por ancestralidade sem serem o serviço.
_STRONG_METHODS = {"cgroup", "mainpid", "execstart", "script"}

# Diretórios padrão de binários do sistema.
_STANDARD_DIRS = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
                  "/usr/lib/", "/usr/libexec/", "/lib/", "/lib64/")

# Mecanismos conhecidos de troca de identidade para root.
_ESCALATORS = {"sudo", "su", "pkexec", "doas", "runuser"}

# Arquivos cujo modo, sozinho, já define uma relação de privilégio.
_SENSITIVE = {"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow", "/etc/sudoers"}
_SECRET = {"/etc/shadow", "/etc/gshadow", "/etc/sudoers"}

# Pseudo-sistemas de arquivos: modos amplos ali são normais (/dev/null 0666).
_PSEUDO_FS = ("/dev/", "/proc/", "/sys/", "/run/")

_URL_RE = re.compile(r"\b[a-z][a-z0-9+.-]*://([^\s/:'\"]+)", re.IGNORECASE)
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_NET_WORDS_RE = re.compile(r"remote|endpoint|https?|url|push|upload|download|fetch|sync|metric",
                           re.IGNORECASE)
_DIR_REASON_RE = re.compile(r"^dir (.+) \d{4}$")

_CONCLUSION_ORDER = {"RISCO": 0, "CONFIG_INADEQUADA": 1, "INCONCLUSIVO": 2, "CONTEXTO_OK": 3}
_SEVERITY_ORDER = {"alta": 0, "média": 1, "baixa": 2, "info": 3}

_NO_PROOF = "Isso NÃO prova exploração."


# --------------------------------------------------------------------------- #
# Utilitários                                                                  #
# --------------------------------------------------------------------------- #
def _basename(path: Optional[str]) -> str:
    return (path or "").rsplit("/", 1)[-1]


def _ts(value: Optional[str]) -> Optional[datetime]:
    """ISO wall-clock naive -> datetime; None se ausente ou ilegível."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _short(text: str, limit: int = 110) -> str:
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _is_root_service(svc: Service) -> bool:
    return svc.user in _ROOT_SERVICE_USERS


def _is_active(svc: Service) -> bool:
    # dataset traz "running"; systemctl show traz ActiveState=active.
    return svc.active in ("running", "active")


def _is_root_proc(proc: Process) -> bool:
    """Root pela identidade real: UID quando coletado (live), senão o nome."""
    if proc.uid is not None:
        return proc.uid == 0
    return proc.user == "root"


def _escalator(proc: Optional[Process]) -> Optional[str]:
    """Nome do mecanismo de elevação (sudo, su…) que o processo executa, se for um.

    O nome sozinho não basta: com caminho absoluto, o executável precisa estar
    em um diretório padrão do sistema (um "sudo" em /tmp não é o sudo).
    """
    if proc is None:
        return None
    name = _basename(proc.exe)
    if name not in _ESCALATORS:
        return None
    if (proc.exe or "").startswith("/") and not proc.exe.startswith(_STANDARD_DIRS):
        return None
    return name


def _service_processes(snap: Snapshot, svc: Service) -> list[Process]:
    """Processos que são o serviço em execução (mapeamento forte)."""
    procs = [p for p in snap.processes.values()
             if p.unit == svc.unit and p.unit_method in _STRONG_METHODS]
    return sorted(procs, key=lambda p: p.pid)


def _render_chain(snap: Snapshot, proc: Process) -> list[str]:
    """Cadeia de ancestralidade do PID 1 até o processo: nome(pid,usuário)."""
    pids = list(reversed(proc.ancestry)) + [proc.pid]
    chain = []
    for pid in pids:
        p = snap.processes.get(pid)
        if p is None:
            chain.append(f"?({pid}, ausente do snapshot)")
            continue
        # "sshd: aluno@pts/0" -> sshd; binário atualizado em disco -> sem " (deleted)"
        name = (_basename(p.exe) or p.cmdline.split(" ")[0]).rstrip(":").replace(" (deleted)", "")
        chain.append(f"{name}({p.pid},{p.user})")
    return chain


# --------------------------------------------------------------------------- #
# Evidências: um construtor por tipo de fonte                                  #
# --------------------------------------------------------------------------- #
def _ev_service(svc: Service) -> Evidence:
    user = svc.user or "root (User= não definido)"
    return Evidence(f'{svc.unit} active={svc.active} user={user} exec="{_short(svc.exec_start)}"',
                    svc.src, "service")


def _ev_process(proc: Process, note: str = "") -> Evidence:
    ids = f" uid={proc.uid} euid={proc.euid}" if proc.uid is not None else ""
    link = f" (vínculo com {proc.unit}: {proc.unit_method})" if proc.unit else ""
    return Evidence(f'pid={proc.pid} ppid={proc.ppid} user={proc.user}{ids} '
                    f'cmd="{_short(proc.cmdline)}"{link}{note}', proc.src, "process")


def _ev_file(fi: FileInfo) -> Evidence:
    return Evidence(f"{fi.path} {fi.type} {fi.owner}:{fi.group} {fi.mode:04o} mtime={fi.mtime}",
                    fi.src, "permission")


def _ev_event(event: TimelineEvent, text: str) -> Evidence:
    return Evidence(text, event.src, "log")


def _kinds(evidence: list[Evidence]) -> list[str]:
    return sorted({e.kind for e in evidence if e.kind})


def _confidence(evidence: list[Evidence]) -> str:
    n = len(_kinds(evidence))
    return "alta" if n >= 3 else "média" if n == 2 else "baixa"


def _finding(correlation: str, title: str, severity: str, conclusion: str,
             chain: list[str], evidence: list[Evidence], interpretation: str,
             hypothesis: str, missing: list[str],
             single_source: str = "INCONCLUSIVO") -> Finding:
    """Monta o Finding e aplica a regra das duas fontes para RISCO."""
    missing = list(missing)
    if conclusion == "RISCO" and len(_kinds(evidence)) < 2:
        conclusion = single_source
        missing.append("uma segunda fonte independente: a ferramenta só conclui RISCO "
                       "com evidência de pelo menos duas fontes")
    return Finding(id="", title=title, correlation=correlation, severity=severity,
                   confidence=_confidence(evidence), conclusion=conclusion, chain=chain,
                   evidence=evidence, interpretation=interpretation,
                   hypothesis=hypothesis, missing=missing)


# --------------------------------------------------------------------------- #
# C4 (parte 1): contexto temporal de um arquivo                                #
# --------------------------------------------------------------------------- #
def _temporal_context(snap: Snapshot, fi: FileInfo, unit: str,
                      procs: list[Process]) -> tuple[list[Evidence], list[str], list[str], list[str]]:
    """Ordena login não-root, mtime do arquivo e (re)início do serviço.

    Devolve (evidências, frases de interpretação, frases de hipótese, ausências).
    Coincidência temporal nunca vira autoria: o texto diz isso explicitamente.
    """
    evidence: list[Evidence] = []
    interp: list[str] = []
    hyp: list[str] = []
    missing: list[str] = []

    mtime = _ts(fi.mtime)
    if mtime is None:
        return evidence, interp, hyp, [f"horário de modificação (mtime) de {fi.path}"]

    logins = [e for e in snap.timeline
              if e.kind == "login" and e.detail.get("user") not in (None, "root") and _ts(e.ts)]
    before = [e for e in logins if _ts(e.ts) <= mtime]
    after = [e for e in logins if _ts(e.ts) > mtime]

    def login_text(e: TimelineEvent) -> str:
        d = e.detail
        return f"login de {d.get('user')} ({d.get('method')}) a partir de {d.get('ip')} em {e.ts}"

    if before:
        last = before[-1]
        evidence.append(_ev_event(last, login_text(last)))
        interp.append(f"Reconstrução temporal: a última modificação de {fi.path} ({fi.mtime}) "
                      f"é posterior ao login de {last.detail.get('user')} ({last.ts}).")
        hyp.append(f"A modificação pode ter ocorrido durante a sessão de "
                   f"{last.detail.get('user')}; é coincidência temporal, não autoria.")
    elif after:
        first = after[0]
        evidence.append(_ev_event(first, login_text(first)))
        interp.append(f"Reconstrução temporal: sem indício de modificação durante a sessão "
                      f"observada — o mtime ({fi.mtime}) é anterior ao login de "
                      f"{first.detail.get('user')} ({first.ts}).")
    else:
        interp.append("Reconstrução temporal: os logs observados não registram login de "
                      "usuário não-root.")

    ran_after = "O serviço iniciou após a última modificação: o conteúdo atual do arquivo " \
                "pode já ter sido executado como root."
    starts = [e for e in snap.timeline
              if e.kind == "service_start" and e.subject == unit and _ts(e.ts) and _ts(e.ts) > mtime]
    late_procs = [p for p in procs if _ts(p.start) and _ts(p.start) > mtime]
    if starts:
        evidence.append(_ev_event(starts[-1], f"{unit} iniciado em {starts[-1].ts}, "
                                              f"após o mtime de {fi.path}"))
        hyp.append(ran_after)
    elif late_procs:
        p = late_procs[0]
        evidence.append(_ev_process(p, f" iniciado em {p.start}, após o mtime de {fi.path}"))
        hyp.append(ran_after)
    else:
        missing.append("início ou reinício do serviço após a última modificação "
                       "(não registrado nos logs observados)")
    return evidence, interp, hyp, missing


# --------------------------------------------------------------------------- #
# C1: processo + serviço + permissão -> hipótese de risco                      #
# --------------------------------------------------------------------------- #
def _path_role(svc: Service, path: str) -> str:
    if path == svc.unit_file:
        return "arquivo de unidade"
    _exe, script = extract_paths(svc.exec_start)
    return "script" if path == script else "executável"


def _writable_meaning(fi: FileInfo, role: str) -> tuple[str, Optional[str]]:
    """Traduz ``nonroot_reason`` em interpretação; devolve também o diretório, se for o caso."""
    reason = fi.nonroot_reason
    m = _DIR_REASON_RE.match(reason)
    if m:
        return (f"O {role} em si não é gravável por não-root, mas o diretório {m.group(1)} é: "
                f"um usuário sem privilégio pode remover o arquivo e criar outro no lugar."), m.group(1)
    if reason.startswith("others:w"):
        return f"O {role} executado como root pode ser alterado por qualquer usuário local (bit o+w).", None
    if reason.startswith("group:w"):
        return (f"O {role} executado como root pode ser alterado por membros de um grupo "
                f"não-root ({reason})."), None
    if reason.startswith("owner="):
        return (f"O {role} executado como root pertence a um usuário não-root ({reason}), "
                f"que pode reescrevê-lo ou alterar suas permissões."), None
    return f"O {role} executado como root é gravável por não-root ({reason}).", None


def _c1_risk(snap: Snapshot, svc: Service, procs: list[Process], fi: FileInfo, role: str) -> Finding:
    meaning, parent_dir = _writable_meaning(fi, role)
    users = [p for p in procs if fi.path in (p.exe, p.script)] or procs[:1]

    evidence = [_ev_service(svc)] + [_ev_process(p) for p in users[:2]] + [_ev_file(fi)]
    if parent_dir and parent_dir in snap.files:
        evidence.append(_ev_file(snap.files[parent_dir]))

    chain = [svc.unit, "User=root"] + [f"PID {p.pid}" for p in users[:1]]
    chain.append(f"{fi.path} ({fi.mode:04o})")
    if parent_dir and parent_dir in snap.files:
        chain.append(f"diretório {parent_dir} ({snap.files[parent_dir].mode:04o})")
    chain.append(f"gravável por não-root [{fi.nonroot_reason}]")

    t_ev, t_interp, t_hyp, t_missing = _temporal_context(snap, fi, svc.unit, procs)
    evidence += t_ev
    hypothesis = ("Um usuário não privilegiado poderia inserir comandos que seriam executados "
                  "como root na próxima execução do serviço. " + _NO_PROOF)
    missing = [f"conteúdo/hash de {fi.path} comparado a uma versão conhecida",
               "autor da última modificação (auditd); o mtime pode ser forjado com touch"]
    if not procs:
        missing.append("processo do serviço no snapshot (mapeamento forte não encontrado)")
    if snap.source == "dataset" and fi.nonroot_reason.startswith("group:w"):
        missing.append("membros do grupo (o dataset não traz participação em grupos)")

    return _finding(
        "C1+C4" if t_ev else "C1",
        f"Serviço root {svc.unit} executa {role} gravável por não-root",
        "alta", "RISCO", chain, evidence,
        " ".join([meaning] + t_interp),
        " ".join([hypothesis] + t_hyp),
        missing + t_missing)


def _c1_inconclusive(svc: Service, procs: list[Process], path: str, role: str) -> Finding:
    evidence = [_ev_service(svc)] + [_ev_process(p) for p in procs[:1]]
    chain = [svc.unit, "User=root"] + [f"PID {p.pid}" for p in procs[:1]] + [path, "permissões não coletadas"]
    return _finding(
        "C1", f"Serviço root {svc.unit}: permissões de {path} não coletadas",
        "média", "INCONCLUSIVO", chain, evidence,
        f"O serviço executa como root um {role} fora dos diretórios padrão do sistema, "
        f"mas não há metadados de permissão para ele.",
        "Sem dono, grupo e modo não é possível dizer se um usuário não privilegiado "
        "consegue alterar o que o serviço executa. Não há base para afirmar risco nem para descartá-lo.",
        [f"permissões de {path} (dono, grupo, modo)",
         f"permissões dos diretórios-pai de {path}"])


def _c1_ok(svc: Service, procs: list[Process], ok_files: list[FileInfo], skipped: list[str]) -> Finding:
    evidence = [_ev_service(svc)] + [_ev_process(p) for p in procs[:1]] + [_ev_file(fi) for fi in ok_files]
    chain = [svc.unit, "User=root"] + [f"{fi.path} ({fi.mode:04o} {fi.owner}:{fi.group})" for fi in ok_files]
    chain.append("alterável apenas por root")
    return _finding(
        "C1", f"Serviço root {svc.unit}: recursos alteráveis apenas por root",
        "info", "CONTEXTO_OK", chain, evidence,
        "Os recursos que o serviço executa como root só podem ser modificados por root.",
        "Nenhuma relação de privilégio insegura foi observada. Executar como root, "
        "isoladamente, não é um achado.",
        [f"permissões de {p} (não coletadas)" for p in skipped])


def _c1_shared_dir(snap: Snapshot, directory: str,
                   hits: list[tuple[Service, list[Process], FileInfo]]) -> Finding:
    """Vários serviços root expostos pela MESMA causa: um achado, não N cópias."""
    dir_fi = snap.files[directory]
    units = sorted({svc.unit for svc, _procs, _fi in hits})
    by_unit = {svc.unit: (svc, procs) for svc, procs, _fi in hits}
    evidence = [_ev_file(dir_fi)]
    for unit in units[:5]:
        svc, procs = by_unit[unit]
        evidence.append(_ev_service(svc))
        evidence += [_ev_process(p) for p in procs[:1]]
    shown = ", ".join(units[:8]) + (f" e mais {len(units) - 8}" if len(units) > 8 else "")
    return _finding(
        "C1", f"{len(units)} serviços root executam arquivos sob {directory}, "
              f"diretório gravável por não-root",
        "alta", "RISCO",
        [f"{len(units)} serviços root", f"{len(hits)} arquivos sob {directory}",
         f"diretório {directory} ({dir_fi.mode:04o} {dir_fi.owner}:{dir_fi.group})",
         f"gravável por não-root [{dir_fi.nonroot_reason}]"],
        evidence,
        f"O diretório {directory} é gravável por não-root [{dir_fi.nonroot_reason}]. Quem o "
        f"controla pode substituir qualquer arquivo abaixo dele, inclusive executáveis e "
        f"arquivos de unidade usados por serviços root: {shown}.",
        "Um usuário não privilegiado poderia trocar o que esses serviços executam como "
        "root. " + _NO_PROOF,
        [f"por que {directory} tem esse dono/modo (histórico de instalação, chown)",
         f"integridade dos arquivos sob {directory} (dpkg --verify, hashes)",
         "lista completa dos arquivos afetados em report.json"
         if len(units) > 5 else "autor da alteração de dono/modo (auditd)"])


def _c1(snap: Snapshot) -> tuple[list[Finding], list[str], set[str]]:
    """Devolve (achados, notas de 'não avaliado', caminhos já tratados)."""
    findings: list[Finding] = []
    notes: list[str] = []
    covered: set[str] = set()
    # diretório-causa -> [(serviço, processos, arquivo, achado individual)]
    by_dir: dict[str, list[tuple[Service, list[Process], FileInfo, Finding]]] = {}

    for unit in sorted(snap.services):
        svc = snap.services[unit]
        if not (_is_active(svc) and _is_root_service(svc)):
            continue
        procs = _service_processes(snap, svc)
        ok_files: list[FileInfo] = []
        skipped: list[str] = []
        flagged = False

        for path in svc.paths:
            role = _path_role(svc, path)
            fi = snap.files.get(path)
            if fi is None or fi.nonroot_writable is None:
                if path.startswith(_STANDARD_DIRS):
                    skipped.append(path)        # binário de sistema sem dados: não avaliado
                    continue
                findings.append(_c1_inconclusive(svc, procs, path, role))
                flagged = True
            elif fi.nonroot_writable:
                finding = _c1_risk(snap, svc, procs, fi, role)
                m = _DIR_REASON_RE.match(fi.nonroot_reason)
                if m and m.group(1) in snap.files:
                    covered.add(m.group(1))
                    by_dir.setdefault(m.group(1), []).append((svc, procs, fi, finding))
                else:
                    findings.append(finding)
                flagged = True
            else:
                ok_files.append(fi)
            covered.add(path)

        if ok_files and not flagged:
            findings.append(_c1_ok(svc, procs, ok_files, skipped))
        elif skipped and not flagged:
            notes.append(f"{unit} (root): permissões de {', '.join(skipped)} não coletadas — "
                         f"caminho padrão de sistema, não avaliado")

    for directory, hits in by_dir.items():
        if len({svc.unit for svc, _p, _f, _x in hits}) == 1:
            findings += [finding for _s, _p, _f, finding in hits]   # causa de um serviço só
        else:
            findings.append(_c1_shared_dir(snap, directory, [h[:3] for h in hits]))
    return findings, notes, covered


# --------------------------------------------------------------------------- #
# C2: processo + PPID + usuário -> contexto de execução                        #
# --------------------------------------------------------------------------- #
def _c2_transition(snap: Snapshot) -> list[Finding]:
    """Processo root cujo pai direto é não-root: a troca de identidade."""
    findings: list[Finding] = []
    for proc in sorted(snap.processes.values(), key=lambda p: p.pid):
        parent = snap.processes.get(proc.ppid)
        if not _is_root_proc(proc) or parent is None or _is_root_proc(parent) or not parent.user:
            continue
        user = parent.user
        chain = _render_chain(snap, proc)
        evidence = [_ev_process(proc)] + [_ev_process(snap.processes[pid])
                                          for pid in proc.ancestry[:3] if pid in snap.processes]
        for e in snap.timeline:
            if e.kind in ("login", "session") and e.detail.get("user") == user:
                what = "login" if e.kind == "login" else "sessão aberta"
                evidence.append(_ev_event(e, f"{what} de {user} em {e.ts}"))

        # O mecanismo é o próprio processo (sudo como root) ou o pai direto: o sudo
        # atual continua vivo como pai do comando, com o UID real do usuário.
        mechanism = _escalator(proc) or _escalator(parent)
        if mechanism:
            findings.append(_finding(
                "C2", f"Elevação de {user} para root via {mechanism} (PID {proc.pid})",
                "info", "CONTEXTO_OK", chain, evidence,
                f"A troca de identidade na cadeia ocorre por {mechanism}, mecanismo "
                f"conhecido e auditável de elevação.",
                "Uso administrativo esperado; a legitimidade depende da política de sudoers.",
                [f"regra de sudoers/polkit que autoriza {user}"]))
            continue

        auth_logs = [l for l in snap.logs if l.ident in _ESCALATORS and user in l.message]
        for l in auth_logs[-2:]:
            evidence.append(Evidence(f"{l.ident}: {_short(l.message)}", l.src, "log"))
        missing = [f"registro de elevação (sudo, su, pkexec) de {user} no período",
                   "comandos executados pelo processo root (histórico do shell, auditd)"]
        if proc.uid is None:
            missing.append("UID real/efetivo do processo e binário SUID usado na transição "
                           "(o dataset não traz UID/EUID)")
        if auth_logs:
            findings.append(_finding(
                "C2", f"Processo root (PID {proc.pid}) descende de sessão de {user}; "
                      f"há registro de elevação no período",
                "média", "INCONCLUSIVO", chain, evidence,
                f"Um processo root é filho direto de um processo de {user} e a cadeia não "
                f"mostra sudo/su, mas os logs registram uso de mecanismo de elevação por {user}.",
                "A elevação pode ter sido legítima e o processo intermediário já ter "
                "encerrado; não é possível associar o registro a este processo.",
                missing))
            continue
        findings.append(_finding(
            "C2", f"Processo root (PID {proc.pid}) descende de sessão de {user} "
                  f"sem sudo/su na cadeia",
            "alta", "RISCO", chain, evidence,
            f"Um processo com identidade root é filho direto de um processo de {user}. "
            f"A cadeia de PPIDs não contém sudo, su ou pkexec, que são as formas "
            f"esperadas de um usuário passar a root.",
            f"{user} pode ter obtido root por um caminho não convencional (binário SUID, "
            f"exploração local) ou por um mecanismo legítimo que o snapshot não mostra. "
            + _NO_PROOF,
            missing))
    return findings


def _c2_suid_context(snap: Snapshot) -> list[Finding]:
    """(live) UID real != UID efetivo 0: processo em contexto SUID."""
    findings: list[Finding] = []
    for proc in sorted(snap.processes.values(), key=lambda p: p.pid):
        if proc.uid is None or proc.euid != 0 or proc.uid == 0:
            continue
        evidence = [_ev_process(proc)]
        fi = snap.files.get(proc.exe or "")
        if fi:
            evidence.append(_ev_file(fi))
        findings.append(_finding(
            "C2", f"Processo de {proc.user} com UID efetivo 0 (PID {proc.pid}, contexto SUID)",
            "info", "INCONCLUSIVO", _render_chain(snap, proc), evidence,
            "O UID real é de um usuário comum e o UID efetivo é 0: o processo age com "
            "privilégio de root por um bit SUID no executável.",
            "Comportamento normal para utilitários SUID do sistema; merece atenção se o "
            "executável não pertencer a um pacote conhecido.",
            [f"pacote de origem de {proc.exe} (dpkg -S) e hash"]))
    return findings


def _c2_user_location(snap: Snapshot, covered: set[str]) -> list[Finding]:
    """Processo root executando a partir de local tipicamente gravável por usuário."""
    prefixes = tuple(d + "/" for d in USER_WRITABLE_DIRS)
    findings: list[Finding] = []
    for proc in sorted(snap.processes.values(), key=lambda p: p.pid):
        if not _is_root_proc(proc):
            continue
        for path in dict.fromkeys(p for p in (proc.exe, proc.script) if p):
            if not path.startswith(prefixes) or path in covered:
                continue
            fi = snap.files.get(path)
            if fi is not None and fi.nonroot_writable is False:
                continue                        # observado e restrito a root
            evidence = [_ev_process(proc)] + ([_ev_file(fi)] if fi else [])
            missing = [f"conteúdo/hash de {path}", "quem criou o arquivo e quando (auditd)"]
            if fi is None:
                missing.insert(0, f"permissões de {path} (dono, grupo, modo)")
            findings.append(_finding(
                "C2", f"Processo root (PID {proc.pid}) executa {path}, em local gravável por usuário",
                "alta", "RISCO", _render_chain(snap, proc) + [path], evidence,
                f"Um processo root executa código a partir de {path}, em um diretório onde "
                f"usuários comuns normalmente podem criar e alterar arquivos."
                + (f" O arquivo é gravável por não-root [{fi.nonroot_reason}]." if fi else ""),
                "Um usuário não privilegiado pode controlar o que root executa. " + _NO_PROOF,
                missing))
    return findings


def _outbound_target(cmdline: str) -> Optional[str]:
    m = _URL_RE.search(cmdline)
    if m:
        return m.group(1)
    for ip in _IP_RE.findall(cmdline):
        if not ip.startswith(("127.", "0.")):
            return ip
    return None


def _c2_outbound(snap: Snapshot) -> list[Finding]:
    """Filho de serviço root com destino externo em argv: contexto, não veredito.

    O gatilho é a relação serviço root -> processo filho -> destino, nunca o
    nome do binário (curl, wget) isoladamente.
    """
    findings: list[Finding] = []
    for proc in sorted(snap.processes.values(), key=lambda p: p.pid):
        svc = snap.services.get(proc.unit or "")
        parent = snap.processes.get(proc.ppid)
        if svc is None or parent is None or parent.unit != proc.unit:
            continue
        if not (_is_root_service(svc) and _is_active(svc) and _is_root_proc(proc)):
            continue
        if any(not _is_root_proc(snap.processes[pid])
               for pid in proc.ancestry if pid in snap.processes):
            continue                            # passou por sessão de usuário: não é o serviço
        target = _outbound_target(proc.cmdline)
        if target is None:
            continue

        related = [l for l in snap.logs if l.unit == svc.unit and
                   (l.pid == proc.pid or target in l.message or _NET_WORDS_RE.search(l.message))]
        evidence = [_ev_service(svc), _ev_process(parent), _ev_process(proc)]
        evidence += [Evidence(f"{l.ident}[{l.pid}]: {_short(l.message)}", l.src, "log")
                     for l in related[:3]]
        if related:
            interp = (f"Um processo filho do serviço root {svc.unit} inicia comunicação de "
                      f"saída para {target}. Os logs do próprio serviço descrevem atividade "
                      f"compatível com essa comunicação.")
        else:
            interp = (f"Um processo filho do serviço root {svc.unit} inicia comunicação de "
                      f"saída para {target}. Nenhum log do serviço descreve essa atividade.")
        findings.append(_finding(
            "C2", f"Serviço root {svc.unit} inicia comunicação de saída para {target}",
            "info", "INCONCLUSIVO",
            _render_chain(snap, proc) + [f"destino {target}"], evidence, interp,
            "A atividade é compatível com o funcionamento normal do serviço (consulta de "
            "status, envio de métricas). Não há base para concluir comando-e-controle, "
            "exfiltração ou malware — nem para descartá-los.",
            [f"resolução e reputação de {target}",
             "configuração do serviço que justifique o destino (unit file, arquivo de config)",
             "conexões estabelecidas e volume trafegado (sockets não disponíveis em dataset)"
             if not snap.sockets else "conteúdo trafegado na conexão",
             "conteúdo/hash do script que origina a chamada"]))
    return findings


def _c2_listeners(snap: Snapshot) -> list[Finding]:
    """(live) Porta em escuta cujo processo não pertence a um serviço dedicado."""
    findings: list[Finding] = []
    seen: set[tuple[int, str]] = set()
    for sock in snap.sockets:
        pid, local = sock.get("pid"), sock.get("local", "")
        if sock.get("state") != "listening" or pid is None:
            continue
        if local.startswith(("127.", "[::1]")) or "%lo" in local:
            continue                            # só alcançável localmente
        if local.split(".")[0].isdigit() and 224 <= int(local.split(".")[0]) <= 239:
            continue                            # multicast (mDNS etc.), não é serviço exposto
        proc = snap.processes.get(pid)
        if proc is None or (pid, local) in seen:
            continue
        if proc.unit and not proc.unit.startswith("user@"):
            continue                            # pertence a um serviço do sistema
        seen.add((pid, local))
        evidence = [Evidence(f"escuta em {local} por {sock.get('process')} (pid={pid})",
                             "ss -tulpnH", "socket"), _ev_process(proc)]
        findings.append(_finding(
            "C2", f"Porta {local} em escuta por processo sem serviço dedicado "
                  f"(PID {pid}, {proc.user})",
            "média", "INCONCLUSIVO", _render_chain(snap, proc) + [f"escuta em {local}"], evidence,
            f"Um processo de {proc.user} aceita conexões em {local} e não está associado "
            f"a nenhuma unidade de serviço do sistema: foi iniciado a partir de uma sessão.",
            "Pode ser uma ferramenta de desenvolvimento ou um serviço exposto fora do "
            "controle do systemd (sem unit, sem log dedicado, sem reinício gerenciado).",
            ["finalidade do processo e quem o iniciou",
             "conexões aceitas e conteúdo servido",
             "regra de firewall para a porta"]))
    return findings


def _c2(snap: Snapshot, covered: set[str]) -> list[Finding]:
    return (_c2_transition(snap) + _c2_suid_context(snap) + _c2_user_location(snap, covered)
            + _c2_outbound(snap) + _c2_listeners(snap))


# --------------------------------------------------------------------------- #
# C3: serviço + arquivo + usuário -> relação de privilégio                     #
# --------------------------------------------------------------------------- #
def _usage(snap: Snapshot, path: str) -> tuple[list[Evidence], bool]:
    """Quem referencia o arquivo: (evidências de uso, se há qualquer referência)."""
    evidence: list[Evidence] = []
    for svc in snap.services.values():
        if path in svc.paths or path in svc.exec_start.split():
            evidence.append(_ev_service(svc))
    for proc in snap.processes.values():
        if path in (proc.exe, proc.script) or path in proc.cmdline.split():
            evidence.append(_ev_process(proc))
    cron_refs = [c for c in snap.cron if path in c.get("paths", [])]
    for c in cron_refs:
        evidence.append(Evidence(f"cron ({c.get('user')}): {_short(c.get('command', ''))}",
                                 c.get("src", ""), "cron"))
    return evidence[:4], bool(evidence)


def _c3_sensitive(fi: FileInfo) -> Finding:
    world_readable = fi.path in _SECRET and bool(fi.mode & 0o004)
    if fi.nonroot_writable or world_readable:
        problem = (f"gravável por não-root [{fi.nonroot_reason}]" if fi.nonroot_writable
                   else "legível por qualquer usuário")
        return _finding(
            "C3", f"Arquivo sensível {fi.path} {problem}", "alta", "RISCO",
            [fi.path, f"{fi.mode:04o} {fi.owner}:{fi.group}", problem], [_ev_file(fi)],
            f"{fi.path} define identidades e privilégios do sistema e está {problem}.",
            "Um usuário não privilegiado poderia alterar ou ler credenciais e regras de "
            "privilégio. " + _NO_PROOF,
            ["conteúdo atual comparado a uma cópia conhecida",
             "autor e data da alteração de permissão (auditd)"],
            single_source="CONFIG_INADEQUADA")
    return _finding(
        "C3", f"Arquivo sensível {fi.path} com modo restrito", "info", "CONTEXTO_OK",
        [fi.path, f"{fi.mode:04o} {fi.owner}:{fi.group}", "não gravável por não-root"],
        [_ev_file(fi)],
        f"{fi.path} não pode ser alterado por usuários não privilegiados.",
        "Configuração esperada.", [])


def _c3_setid(snap: Snapshot, fi: FileInfo) -> Finding:
    bit = "SUID" if fi.suid else "SGID"
    used_ev, used = _usage(snap, fi.path)
    evidence = [_ev_file(fi)] + used_ev
    usage = ("Há processo, serviço ou cron observado que o utiliza." if used else
             "Nenhum processo, serviço ou entrada de cron observados o utiliza.")
    chain = [fi.path, f"{fi.mode:04o} {fi.owner}:{fi.group}", f"bit {bit}",
             "fora dos diretórios padrão"]
    missing = [f"origem de {fi.path} (pacote: dpkg -S) e hash",
               "o que o binário faz (strings, execução controlada)",
               "quem o criou e quando (auditd); o mtime pode ser forjado"]
    if fi.nonroot_writable:
        return _finding(
            "C3", f"Binário {bit} {fi.path} gravável por não-root", "alta", "RISCO",
            chain + [f"gravável por não-root [{fi.nonroot_reason}]"], evidence,
            f"O arquivo tem bit {bit} de {fi.owner} e pode ser alterado por um usuário "
            f"não privilegiado. {usage}",
            "Quem altera o arquivo define o que roda com a identidade do dono. " + _NO_PROOF,
            missing, single_source="CONFIG_INADEQUADA")
    return _finding(
        "C3", f"Binário {bit} fora dos diretórios padrão: {fi.path}", "média", "INCONCLUSIVO",
        chain, evidence,
        f"Quem executa o arquivo obtém a identidade efetiva de {fi.owner} (bit {bit}), "
        f"e ele está fora dos diretórios de binários do sistema. {usage}",
        "Pode ser uma ferramenta administrativa instalada localmente ou um mecanismo de "
        "escalação/persistência. A evidência disponível não permite distinguir.",
        missing)


def _c3_orphan_writable(snap: Snapshot, fi: FileInfo) -> Finding:
    missing = ["unidades de serviço inativas ou timers que referenciem o arquivo",
               "histórico de execução do arquivo"]
    if not snap.cron:
        missing.insert(0, "crontabs e timers (não disponíveis nesta coleta)")
    return _finding(
        "C3", f"{fi.path} gravável por qualquer usuário, sem vínculo com execução privilegiada",
        "baixa", "CONFIG_INADEQUADA",
        [fi.path, f"{fi.mode:04o} {fi.owner}:{fi.group}", "o+w", "sem referência observada"],
        [_ev_file(fi)],
        f"O {'diretório' if fi.type == 'directory' else 'arquivo'} é gravável por qualquer "
        f"usuário (o+w). Nenhum serviço, processo ou entrada de cron observados o referencia.",
        "Permissão excessiva sem impacto de privilégio demonstrado. Passaria a ser risco "
        "se algum mecanismo privilegiado ainda não observado o executasse.",
        missing)


def _c3(snap: Snapshot, covered: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(snap.files):
        fi = snap.files[path]
        if path in covered or path.startswith(_PSEUDO_FS):
            continue
        if path in _SENSITIVE or path.startswith("/etc/sudoers.d/"):
            findings.append(_c3_sensitive(fi))
        elif (fi.suid or fi.sgid) and fi.type == "file" and not path.startswith(_STANDARD_DIRS):
            findings.append(_c3_setid(snap, fi))
        elif fi.world_writable and not (fi.type == "directory" and fi.mode & 0o1000):
            if not _usage(snap, path)[1]:
                findings.append(_c3_orphan_writable(snap, fi))
    return findings


# --------------------------------------------------------------------------- #
# C4 (parte 2): processo + serviço + log -> inconsistência de estado           #
# --------------------------------------------------------------------------- #
def _c4_state(snap: Snapshot) -> list[Finding]:
    """Log diz que o serviço parou, snapshot mostra o processo em execução."""
    last: dict[str, TimelineEvent] = {}
    for event in snap.timeline:
        if event.kind in ("service_start", "service_stop") and _ts(event.ts):
            last[event.subject] = event

    findings: list[Finding] = []
    for unit in sorted(last):
        event, svc = last[unit], snap.services.get(unit)
        if event.kind != "service_stop" or svc is None or not _is_active(svc):
            continue
        # No live, um processo iniciado depois da parada é só um reinício.
        procs = [p for p in _service_processes(snap, svc)
                 if not (_ts(p.start) and _ts(p.start) > _ts(event.ts))]
        if not procs:
            continue
        proc = procs[0]
        missing = ["tipo da unidade (Type=, timers associados)",
                   "logs anteriores e posteriores ao intervalo observado"]
        if proc.start is None:
            missing.insert(0, "horário de início do processo (/proc/PID/stat; ausente em dataset)")
        findings.append(_finding(
            "C4", f"{unit}: log registra desativação, mas o processo segue em execução",
            "info", "INCONCLUSIVO",
            [unit, f"desativado em {event.ts} (log)", f"PID {proc.pid} em execução (snapshot)"],
            [_ev_event(event, f"{unit} desativado/parado em {event.ts}"),
             _ev_service(svc), _ev_process(proc)],
            f"O log registra a desativação de {unit} em {event.ts}, mas o snapshot mostra a "
            f"unidade como ativa e o PID {proc.pid} em execução.",
            "Possível reinício não registrado, unidade acionada periodicamente, "
            "reutilização de PID ou log incompleto/rotacionado. Nenhuma dessas explicações "
            "está confirmada.",
            missing))
    return findings


def _missing_log_pids(snap: Snapshot) -> list[str]:
    """PIDs citados em log que não estão no snapshot: observação, não achado."""
    seen: dict[int, str] = {}
    for log in snap.logs:
        if log.pid is not None and log.pid not in snap.processes:
            seen.setdefault(log.pid, log.ident)
    if not seen:
        return []
    sample = ", ".join(f"{ident}[{pid}]" for pid, ident in list(seen.items())[:5])
    more = f" e mais {len(seen) - 5}" if len(seen) > 5 else ""
    return [f"{len(seen)} PID(s) citados em log não estão no snapshot de processos "
            f"(processo encerrado, efêmero ou não coletado): {sample}{more}"]


# --------------------------------------------------------------------------- #
# Entrada                                                                      #
# --------------------------------------------------------------------------- #
def analyze(snap: Snapshot) -> tuple[list[Finding], list[str]]:
    """Executa C1–C4. Devolve (achados ordenados, observações de 'não avaliado')."""
    findings, notes, covered = _c1(snap)
    findings += _c2(snap, covered)
    findings += _c3(snap, covered)
    findings += _c4_state(snap)
    notes += _missing_log_pids(snap)

    findings.sort(key=lambda f: (_CONCLUSION_ORDER.get(f.conclusion, 9),
                                 _SEVERITY_ORDER.get(f.severity, 9), f.correlation, f.title))
    for i, finding in enumerate(findings, start=1):
        finding.id = f"F-{i:03d}"
    return findings, notes


def run(snap: Snapshot) -> list[Finding]:
    """Interface combinada no handoff: Snapshot -> lista de Findings."""
    return analyze(snap)[0]
