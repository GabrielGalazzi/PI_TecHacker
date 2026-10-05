"""Contrato de dados da ferramenta.

Este módulo define o **Snapshot** e suas entidades (lado Galazzi). Tanto o modo
dataset quanto o modo live produzem exatamente estas estruturas, de forma que a
etapa de correlação (Sardou) leia sempre o mesmo formato.

Princípio central: cada fato registra *de onde veio* (`src`), e tudo o que não
pôde ser coletado é listado em `Snapshot.gaps`.

O lado Finding (Evidence, Finding) é acrescentado por Sardou em S1, ao final
deste arquivo, na seção demarcada.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional


@dataclass
class Process:
    """Um processo observado no snapshot."""

    pid: int                       # identificador do processo
    ppid: int                      # identificador do processo pai
    user: str                      # usuário dono (nome textual)
    uid: Optional[int]             # UID real; None no modo dataset (não coletado)
    euid: Optional[int]            # UID efetivo; None no modo dataset
    state: str                     # estado (ex.: "Ss", "S", "R"); do stat/status
    cmdline: str                   # linha de comando completa
    exe: Optional[str]             # executável (argv[0] ou readlink /proc/pid/exe)
    script: Optional[str]          # script alvo quando exe é um interpretador (bash, python3…)
    start: Optional[str]           # horário de início do processo (ISO); None no dataset
    unit: Optional[str]            # unidade systemd mapeada, se houver
    unit_method: Optional[str]     # como o mapeamento ocorreu: cgroup|mainpid|execstart|script|ancestor|name
    ancestry: list[int] = field(default_factory=list)  # PIDs do pai até 1
    src: str = ""                  # proveniência, ex.: "processes.csv:5" ou "/proc/2417/status"


@dataclass
class Service:
    """Uma unidade de serviço (systemd) em execução."""

    unit: str                      # nome da unidade, ex.: "backup-agent.service"
    active: str                    # estado ativo, ex.: "running"
    user: str                      # usuário configurado (vazio ou "root" = root)
    exec_start: str                # comando de ExecStart (já sem prefixos systemd)
    main_pid: Optional[int]        # MainPID, quando conhecido (live)
    unit_file: Optional[str]       # caminho do arquivo de unidade (FragmentPath), quando conhecido
    paths: list[str] = field(default_factory=list)  # caminhos referenciados (binário, script, unit file)
    src: str = ""                  # proveniência, ex.: "services.txt:4"


@dataclass
class FileInfo:
    """Metadados de um arquivo ou diretório e conclusões de permissão derivadas."""

    path: str                      # caminho absoluto
    type: str                      # "file" ou "directory"
    owner: str                     # dono (nome)
    group: str                     # grupo (nome)
    mode: int                      # modo como inteiro (ex.: 0o777), derivado de int(mode,8)
    mtime: Optional[str]           # horário de modificação (ISO); None se ausente
    world_writable: bool           # bit o+w
    group_writable: bool           # bit g+w
    suid: bool                     # bit setuid
    sgid: bool                     # bit setgid
    nonroot_writable: Optional[bool]  # gravável por não-root? None quando não há dados de permissão
    nonroot_reason: str            # justificativa, ex.: "others:w", "owner=aluno", "dir /opt/x 0777"
    src: str = ""                  # proveniência, ex.: "permissions.csv:3" ou "/opt/backup/backup.sh"


@dataclass
class LogEvent:
    """Uma linha de log já estruturada."""

    ts: Optional[str]              # horário do evento (ISO, wall-clock); None se não parseável
    ident: str                     # identificador (ex.: "sshd", "systemd")
    pid: Optional[int]             # PID associado, quando presente
    unit: Optional[str]            # unidade systemd associada (live: _SYSTEMD_UNIT)
    message: str                   # texto da mensagem
    src: str = ""                  # proveniência, ex.: "journal.log:6"


@dataclass
class TimelineEvent:
    """Um evento tipado da linha do tempo, derivado de logs/metadados/arquivos."""

    ts: Optional[str]              # horário do evento (ISO, wall-clock)
    kind: str                      # service_start|service_stop|login|session|process_start|file_mtime
    subject: str                   # sujeito: unidade / usuário / pid / caminho
    detail: dict[str, Any] = field(default_factory=dict)  # ex.: {"user":"aluno","ip":"...","method":"publickey"}
    src: str = ""                  # proveniência da origem do evento


@dataclass
class Snapshot:
    """Estado normalizado completo de um endpoint, em um instante."""

    source: str                    # "dataset" ou "live"
    host: str                      # nome do host
    taken_at: Optional[str]        # horário da coleta (ISO), quando conhecido
    ran_as_root: bool              # a coleta rodou como root? (afeta a visibilidade)
    processes: dict[int, Process] = field(default_factory=dict)   # pid -> Process
    services: dict[str, Service] = field(default_factory=dict)    # unit -> Service
    files: dict[str, FileInfo] = field(default_factory=dict)      # path -> FileInfo
    logs: list[LogEvent] = field(default_factory=list)            # eventos de log crus (estruturados)
    timeline: list[TimelineEvent] = field(default_factory=list)   # eventos tipados, ordenados por tempo
    sockets: list[dict] = field(default_factory=list)             # extras (live); pode estar vazio
    cron: list[dict] = field(default_factory=list)                # extras (live); pode estar vazio
    gaps: list[str] = field(default_factory=list)                 # o que NÃO pôde ser coletado

    def to_dict(self) -> dict:
        """Serializa o Snapshot para um dict pronto para JSON (dataclasses.asdict).

        As chaves inteiras de `processes` são convertidas para string, porque
        JSON só admite chaves textuais.
        """
        data = asdict(self)
        data["processes"] = {str(pid): proc for pid, proc in data["processes"].items()}
        return data


# ---------------------------------------------------------------------------
# Lado Finding (Sardou — S1): o resultado da correlação.
#
# A separação pedida pelo enunciado está na própria estrutura: `evidence` só
# guarda fatos observados (cada um com `src`), enquanto `interpretation`,
# `hypothesis` e `missing` são campos distintos e não carregam proveniência.
# ---------------------------------------------------------------------------
@dataclass
class Evidence:
    """Um fato efetivamente observado, com a origem que permite conferi-lo."""

    text: str                      # o que foi observado, sem interpretação
    src: str                       # proveniência herdada do fato do Snapshot
    kind: str = ""                 # tipo de fonte: service|process|permission|log|socket


@dataclass
class Finding:
    """Uma relação entre evidências e o que se pode (ou não) concluir dela."""

    id: str                        # identificador no relatório, ex.: "F-001"
    title: str                     # resumo de uma linha
    correlation: str               # correlação que o gerou: "C1".."C4" (ou "C1+C4")
    severity: str                  # impacto SE a hipótese for verdadeira: alta|média|baixa|info
    confidence: str                # nº de tipos de fonte independentes: alta(>=3)|média(2)|baixa(1)
    conclusion: str                # RISCO|CONFIG_INADEQUADA|INCONCLUSIVO|CONTEXTO_OK
    chain: list[str] = field(default_factory=list)          # cadeia da relação, elo a elo
    evidence: list[Evidence] = field(default_factory=list)  # o que foi observado
    interpretation: str = ""       # significado técnico atribuído à evidência
    hypothesis: str = ""           # possível explicação para a relação encontrada
    missing: list[str] = field(default_factory=list)        # o que confirmaria ou rejeitaria a hipótese
