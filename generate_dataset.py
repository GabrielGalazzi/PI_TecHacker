#!/usr/bin/env python3
"""
Endpoint Investigator - Training Dataset Generator

Gera datasets sintéticos para treinamento e testes de uma ferramenta de
investigação de endpoints Linux. Os datasets são fictícios e não representam
incidentes reais.

Uso:
  python3 generate_dataset.py --level basic --output training/basic-001
  python3 generate_dataset.py --level intermediate --output training/intermediate-001
  python3 generate_dataset.py --level challenge --output training/challenge-001 --seed 42
  python3 generate_dataset.py --batch 10 --level intermediate --output training/

Níveis:
  basic       - cenários simples e pouco ambíguos
  intermediate- mistura situações normais e achados relevantes
  challenge   - inclui relações ambíguas e ruído

O script produz:
  processes.csv
  permissions.csv
  services.txt
  journal.log
  README.txt
  metadata.json
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import string
from datetime import datetime, timedelta, timezone
from pathlib import Path


BASE_IPS = [
    "10.20.30.10", "10.20.30.11", "10.20.30.12", "10.20.30.20",
    "10.20.30.30", "10.20.30.40", "10.20.30.50",
]
REMOTE_IPS = ["198.51.100.12", "198.51.100.44", "203.0.113.25", "203.0.113.80"]
DOMAINS = [
    "updates.example.invalid",
    "metrics.example.invalid",
    "backup.example.invalid",
    "repo.example.invalid",
]


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S-03:00")


def rand_name(prefix: str, n: int = 6) -> str:
    chars = string.ascii_lowercase + string.digits
    return prefix + "-" + "".join(random.choice(chars) for _ in range(n))


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _normal_raw() -> tuple[list, list, list, list]:
    """Dados crus (tuplas) do cenário normal, reutilizáveis por random_noise.

    Retorna as listas antes de passarem por build(), para que random_noise
    possa acrescentar novas tuplas cruas e chamar build() uma única vez.
    """
    processes = [
        (1, 0, "root", "Ss", "/sbin/init"),
        (612, 1, "root", "Ss", "/usr/sbin/sshd -D"),
        (701, 1, "root", "Ss", "/usr/sbin/cron -f"),
        (733, 1, "www-data", "S", "/usr/sbin/apache2 -k start"),
        (744, 733, "www-data", "S", "/usr/sbin/apache2 -k start"),
        (1204, 612, "aluno", "Ss", "sshd: aluno@pts/0"),
        (1212, 1204, "aluno", "S", "/bin/bash"),
        (1234, 1212, "aluno", "S", "/usr/bin/python3 /home/aluno/check.py"),
    ]
    permissions = [
        ("/opt/app", "directory", "root", "root", "0755"),
        ("/opt/app/check.py", "file", "root", "root", "0755"),
        ("/etc/shadow", "file", "root", "shadow", "0640"),
        ("/usr/local/bin/report-sync", "file", "root", "root", "0755"),
        ("/home/aluno/check.py", "file", "aluno", "aluno", "0755"),
    ]
    services = [
        ("ssh.service", "running", "root", "/usr/sbin/sshd -D"),
        ("apache2.service", "running", "root", "/usr/sbin/apachectl start"),
        ("cron.service", "running", "root", "/usr/sbin/cron -f"),
    ]
    logs = [
        (0, "systemd[1]: Started ssh.service - OpenBSD Secure Shell server."),
        (2, "systemd[1]: Started apache2.service - The Apache HTTP Server."),
        (8, "sshd[1204]: Accepted publickey for aluno from 10.20.30.44 port 51518 ssh2"),
        (10, "systemd-logind[640]: New session 7 of user aluno."),
        (15, "python3[1234]: routine check completed status=OK"),
    ]
    return processes, permissions, services, logs


def scenario_normal(start: datetime) -> dict:
    processes, permissions, services, logs = _normal_raw()
    return build(start, processes, permissions, services, logs, "normal")


def scenario_permission(start: datetime) -> dict:
    d = scenario_normal(start)
    d["permissions"].extend([
        {"path": "/opt/reports/report.sh", "type": "file", "owner": "root", "group": "root", "mode": "0777", "mtime": iso(start - timedelta(days=2))},
        {"path": "/opt/reports", "type": "directory", "owner": "root", "group": "root", "mode": "0755", "mtime": iso(start - timedelta(days=3))},
    ])
    d["readme_extra"] = (
        "Há uma permissão excessivamente ampla em um arquivo, mas o dataset não "
        "estabelece que ele seja executado por um serviço privilegiado. O aluno "
        "deve diferenciar configuração inadequada de evidência de exploração."
    )
    return d


def scenario_privileged_service(start: datetime) -> dict:
    processes = [
        (1, 0, "root", "Ss", "/sbin/init"),
        (612, 1, "root", "Ss", "/usr/sbin/sshd -D"),
        (821, 1, "root", "Ss", "/usr/sbin/cron -f"),
        (2417, 1, "root", "Ss", "/bin/bash /opt/backup/backup.sh"),
        (2421, 2417, "root", "S", "/usr/bin/curl -fsS https://updates.example.invalid/status"),
    ]
    permissions = [
        ("/opt/backup", "directory", "root", "root", "0755"),
        ("/opt/backup/backup.sh", "file", "root", "root", "0700"),
        ("/opt/backup/config.ini", "file", "root", "backup", "0640"),
    ]
    services = [
        ("ssh.service", "running", "root", "/usr/sbin/sshd -D"),
        ("cron.service", "running", "root", "/usr/sbin/cron -f"),
        ("backup-agent.service", "running", "root", "/bin/bash /opt/backup/backup.sh"),
    ]
    logs = [
        (0, "systemd[1]: Started ssh.service - OpenBSD Secure Shell server."),
        (60, "systemd[1]: Starting backup-agent.service - Internal Backup Agent..."),
        (63, "backup-agent[2417]: backup job started"),
        (64, "backup-agent[2417]: checking remote status endpoint"),
        (65, "backup-agent[2417]: backup completed with status=OK"),
        (66, "systemd[1]: backup-agent.service: Deactivated successfully."),
    ]
    d = build(start, processes, permissions, services, logs, "privileged_service")
    d["readme_extra"] = (
        "O serviço executa como root, mas o script está restrito a root. O objetivo "
        "é evitar a regra simplista 'serviço root = vulnerabilidade'."
    )
    return d


def scenario_correlation(start: datetime) -> dict:
    processes = [
        (1, 0, "root", "Ss", "/sbin/init"),
        (612, 1, "root", "Ss", "/usr/sbin/sshd -D"),
        (821, 1, "root", "Ss", "/usr/sbin/cron -f"),
        (2417, 1, "root", "Ss", "/bin/bash /opt/backup/backup.sh"),
        (2421, 2417, "root", "S", "/usr/bin/curl -fsS https://updates.example.invalid/status"),
        (2630, 612, "aluno", "Ss", "sshd: aluno@pts/0"),
        (2638, 2630, "aluno", "S", "/bin/bash"),
    ]
    permissions = [
        ("/opt/backup", "directory", "root", "root", "0755"),
        ("/opt/backup/backup.sh", "file", "root", "root", "0777"),
        ("/opt/backup/config.ini", "file", "root", "backup", "0640"),
        ("/usr/local/bin/report-sync", "file", "root", "root", "4755"),
    ]
    services = [
        ("ssh.service", "running", "root", "/usr/sbin/sshd -D"),
        ("cron.service", "running", "root", "/usr/sbin/cron -f"),
        ("backup-agent.service", "running", "root", "/bin/bash /opt/backup/backup.sh"),
    ]
    logs = [
        (0, "systemd[1]: Started ssh.service - OpenBSD Secure Shell server."),
        (120, "systemd[1]: Starting backup-agent.service - Internal Backup Agent..."),
        (123, "backup-agent[2417]: backup job started"),
        (124, "backup-agent[2417]: checking remote status endpoint"),
        (125, "backup-agent[2417]: backup completed with status=OK"),
        (1500, "sshd[2630]: Accepted publickey for aluno from 10.20.30.44 port 51518 ssh2"),
        (1502, "systemd-logind[640]: New session 9 of user aluno."),
    ]
    d = build(start, processes, permissions, services, logs, "correlation")
    d["readme_extra"] = (
        "Este é um cenário de correlação. A combinação serviço privilegiado + script "
        "world-writable deve gerar um finding de risco. O dataset não prova que houve exploração."
    )
    return d


def scenario_ambiguous(start: datetime) -> dict:
    processes = [
        (1, 0, "root", "Ss", "/sbin/init"),
        (612, 1, "root", "Ss", "/usr/sbin/sshd -D"),
        (901, 1, "root", "Ss", "/usr/sbin/cron -f"),
        (1500, 1, "root", "S", "/usr/bin/python3 /opt/monitor/agent.py"),
        (1510, 1500, "root", "S", "/usr/bin/curl -fsS https://metrics.example.invalid/v1/push"),
        (1632, 612, "aluno", "Ss", "sshd: aluno@pts/0"),
        (1640, 1632, "aluno", "S", "/bin/bash"),
        (1645, 1640, "aluno", "S", "/usr/bin/python3 /home/aluno/check.py"),
    ]
    permissions = [
        ("/opt/monitor", "directory", "root", "root", "0755"),
        ("/opt/monitor/agent.py", "file", "root", "root", "0755"),
        ("/home/aluno/check.py", "file", "aluno", "aluno", "0755"),
    ]
    services = [
        ("ssh.service", "running", "root", "/usr/sbin/sshd -D"),
        ("cron.service", "running", "root", "/usr/sbin/cron -f"),
        ("monitor-agent.service", "running", "root", "/usr/bin/python3 /opt/monitor/agent.py"),
    ]
    logs = [
        (0, "systemd[1]: Started ssh.service - OpenBSD Secure Shell server."),
        (20, "systemd[1]: Started monitor-agent.service - Monitoring Agent."),
        (22, "monitor-agent[1500]: sending metrics batch=12"),
        (25, "monitor-agent[1510]: remote status=200"),
        (1600, "sshd[1632]: Accepted publickey for aluno from 10.20.30.44 port 51590 ssh2"),
        (1615, "python3[1645]: check completed status=OK"),
    ]
    d = build(start, processes, permissions, services, logs, "ambiguous")
    d["readme_extra"] = (
        "Há uma conexão externa iniciada por um serviço root. Sem outras evidências, "
        "isso não deve ser tratado automaticamente como C2 ou malware. O aluno deve investigar contexto."
    )
    return d


def scenario_tampered_after_login(start: datetime) -> dict:
    """Serviço root cujo script 0777 foi modificado DEPOIS de um login não-root,
    e o serviço reinicia após a modificação. Alvo: RISCO/alta, confiança alta (C1+C4)."""
    processes = [
        (1, 0, "root", "Ss", "/sbin/init"),
        (612, 1, "root", "Ss", "/usr/sbin/sshd -D"),
        (821, 1, "root", "Ss", "/usr/sbin/cron -f"),
        (2417, 1, "root", "Ss", "/bin/bash /opt/backup/backup.sh"),
        (2630, 612, "aluno", "Ss", "sshd: aluno@pts/0"),
        (2638, 2630, "aluno", "S", "/bin/bash"),
    ]
    permissions = [
        ("/opt/backup", "directory", "root", "root", "0755"),
        ("/opt/backup/backup.sh", "file", "root", "root", "0777"),
        ("/opt/backup/config.ini", "file", "root", "backup", "0640"),
    ]
    services = [
        ("ssh.service", "running", "root", "/usr/sbin/sshd -D"),
        ("cron.service", "running", "root", "/usr/sbin/cron -f"),
        ("backup-agent.service", "running", "root", "/bin/bash /opt/backup/backup.sh"),
    ]
    logs = [
        (0, "systemd[1]: Started ssh.service - OpenBSD Secure Shell server."),
        (100, "sshd[2630]: Accepted publickey for aluno from 10.20.30.44 port 51518 ssh2"),
        (102, "systemd-logind[640]: New session 9 of user aluno."),
        (300, "systemd[1]: Starting backup-agent.service - Internal Backup Agent..."),
        (303, "backup-agent[2417]: backup job started"),
        (305, "backup-agent[2417]: backup completed with status=OK"),
    ]
    d = build(start, processes, permissions, services, logs, "tampered_after_login")
    # mtime do script APÓS o login (100s) e ANTES do reinício do serviço (300s).
    for perm in d["permissions"]:
        if perm["path"] == "/opt/backup/backup.sh":
            perm["mtime"] = iso(start + timedelta(seconds=200))
    d["readme_extra"] = (
        "O script executado por serviço root está 0777 e sua mtime é posterior a um "
        "login SSH não privilegiado; o serviço reinicia depois disso. A correlação "
        "temporal deve elevar a confiança, sem provar exploração."
    )
    return d


def scenario_writable_parent_dir(start: datetime) -> dict:
    """Script 0755 root, mas o diretório que o contém é 0777. Alvo: RISCO/alta
    pela razão de diretório-pai gravável (o arquivo pode ser substituído)."""
    processes = [
        (1, 0, "root", "Ss", "/sbin/init"),
        (612, 1, "root", "Ss", "/usr/sbin/sshd -D"),
        (821, 1, "root", "Ss", "/usr/sbin/cron -f"),
        (2417, 1, "root", "Ss", "/bin/bash /opt/backup/backup.sh"),
    ]
    permissions = [
        ("/opt/backup", "directory", "root", "root", "0777"),
        ("/opt/backup/backup.sh", "file", "root", "root", "0755"),
        ("/opt/backup/config.ini", "file", "root", "backup", "0640"),
    ]
    services = [
        ("ssh.service", "running", "root", "/usr/sbin/sshd -D"),
        ("cron.service", "running", "root", "/usr/sbin/cron -f"),
        ("backup-agent.service", "running", "root", "/bin/bash /opt/backup/backup.sh"),
    ]
    logs = [
        (0, "systemd[1]: Started ssh.service - OpenBSD Secure Shell server."),
        (60, "systemd[1]: Starting backup-agent.service - Internal Backup Agent..."),
        (63, "backup-agent[2417]: backup job started"),
        (65, "backup-agent[2417]: backup completed with status=OK"),
    ]
    d = build(start, processes, permissions, services, logs, "writable_parent_dir")
    d["readme_extra"] = (
        "O script em si está com modo seguro (0755), mas o diretório pai está 0777. "
        "Um usuário não privilegiado pode substituir o arquivo. A ferramenta deve "
        "sinalizar risco pela permissão do diretório, não do arquivo."
    )
    return d


def scenario_user_to_root(start: datetime) -> dict:
    """Shell root descende de uma sessão de usuário (aluno) sem sudo/su na cadeia.
    Alvo: C2 RISCO/alta (contexto de execução suspeito)."""
    processes = [
        (1, 0, "root", "Ss", "/sbin/init"),
        (612, 1, "root", "Ss", "/usr/sbin/sshd -D"),
        (821, 1, "root", "Ss", "/usr/sbin/cron -f"),
        (2630, 612, "aluno", "Ss", "sshd: aluno@pts/0"),
        (2638, 2630, "aluno", "S", "/bin/bash"),
        (2650, 2638, "root", "S", "/bin/bash"),
    ]
    permissions = [
        ("/etc/shadow", "file", "root", "shadow", "0640"),
        ("/home/aluno", "directory", "aluno", "aluno", "0755"),
    ]
    services = [
        ("ssh.service", "running", "root", "/usr/sbin/sshd -D"),
        ("cron.service", "running", "root", "/usr/sbin/cron -f"),
    ]
    logs = [
        (0, "systemd[1]: Started ssh.service - OpenBSD Secure Shell server."),
        (100, "sshd[2630]: Accepted publickey for aluno from 10.20.30.44 port 51518 ssh2"),
        (102, "systemd-logind[640]: New session 9 of user aluno."),
    ]
    d = build(start, processes, permissions, services, logs, "user_to_root")
    d["readme_extra"] = (
        "Um processo root (pid 2650) descende diretamente de uma sessão do usuário "
        "aluno, sem sudo/su/pkexec na cadeia de ancestralidade. A cadeia de PPIDs é "
        "a evidência central para o contexto de execução (C2)."
    )
    return d


def scenario_missing_evidence(start: datetime) -> dict:
    """Serviço root referencia /opt/x/run.sh, ausente de permissions.csv.
    Alvo: INCONCLUSIVO (permissões do script não coletadas)."""
    processes = [
        (1, 0, "root", "Ss", "/sbin/init"),
        (612, 1, "root", "Ss", "/usr/sbin/sshd -D"),
        (821, 1, "root", "Ss", "/usr/sbin/cron -f"),
        (3001, 1, "root", "Ss", "/bin/bash /opt/x/run.sh"),
    ]
    permissions = [
        ("/etc/shadow", "file", "root", "shadow", "0640"),
        ("/opt/app", "directory", "root", "root", "0755"),
    ]
    services = [
        ("ssh.service", "running", "root", "/usr/sbin/sshd -D"),
        ("cron.service", "running", "root", "/usr/sbin/cron -f"),
        ("inventory-agent.service", "running", "root", "/bin/bash /opt/x/run.sh"),
    ]
    logs = [
        (0, "systemd[1]: Started ssh.service - OpenBSD Secure Shell server."),
        (50, "systemd[1]: Started inventory-agent.service - Inventory Agent."),
        (52, "inventory-agent[3001]: collecting inventory"),
    ]
    d = build(start, processes, permissions, services, logs, "missing_evidence")
    d["readme_extra"] = (
        "O serviço root executa /opt/x/run.sh, mas esse caminho não aparece em "
        "permissions.csv. Sem os metadados do arquivo, não é possível concluir sobre "
        "risco: a saída correta é INCONCLUSIVO, listando a evidência ausente."
    )
    return d


def random_noise(start: datetime, seed: int) -> dict:
    """Gera um cenário intermediário aleatório a partir de padrões conhecidos."""
    random.seed(seed)
    # Correção de bug: partir dos dados CRUS (tuplas) do cenário normal.
    # A versão original reutilizava scenario_normal(start), cujo dict já havia
    # passado por build(), e reenviava esses dicts a build() -> ValueError.
    raw_processes, raw_permissions, raw_services, raw_logs = _normal_raw()
    processes = list(raw_processes)
    permissions = list(raw_permissions)
    services = list(raw_services)
    logs = list(raw_logs)

    # Ajustes aleatórios de PID e uma situação de interesse.
    pid = random.randint(2000, 6000)
    service_name = random.choice(["backup-agent", "report-sync", "inventory-agent"])
    script = f"/opt/{service_name}/run.sh"
    owner = "root"
    mode = random.choice(["0750", "0700", "0770", "0777"])
    processes.append((pid, 1, "root", "Ss", f"/bin/bash {script}"))
    permissions.append((f"/opt/{service_name}", "directory", "root", "root", "0755"))
    permissions.append((script, "file", owner, "root", mode))
    services.append((f"{service_name}.service", "running", "root", f"/bin/bash {script}"))
    logs.append((random.randint(100, 300), f"systemd[1]: Started {service_name}.service - {service_name} service."))
    return build(start, processes, permissions, services, logs, "random")


def build(start, processes, permissions, services, logs, kind):
    return {
        "kind": kind,
        "processes": [
            {"timestamp": iso(start + timedelta(seconds=i * 2)), "pid": str(pid), "ppid": str(ppid),
             "user": user, "stat": stat, "cmd": cmd}
            for i, (pid, ppid, user, stat, cmd) in enumerate(processes)
        ],
        "permissions": [
            {"path": path, "type": typ, "owner": owner, "group": group, "mode": mode,
             "mtime": iso(start - timedelta(days=(i % 12), minutes=i))}
            for i, (path, typ, owner, group, mode) in enumerate(permissions)
        ],
        "services": services,
        "logs": [
            (start + timedelta(seconds=offset), message) for offset, message in logs
        ],
        "readme_extra": "",
    }


# Cenários nomeados e determinísticos, selecionáveis por --scenario.
# "random" é tratado à parte porque exige um seed.
SCENARIOS = {
    "normal": scenario_normal,
    "permission": scenario_permission,
    "privileged_service": scenario_privileged_service,
    "correlation": scenario_correlation,
    "ambiguous": scenario_ambiguous,
    "tampered_after_login": scenario_tampered_after_login,
    "writable_parent_dir": scenario_writable_parent_dir,
    "user_to_root": scenario_user_to_root,
    "missing_evidence": scenario_missing_evidence,
}
SCENARIO_NAMES = list(SCENARIOS) + ["random"]


def make_dataset(level: str, seed: int | None, out_dir: Path,
                 scenario: str | None = None) -> None:
    if seed is not None:
        random.seed(seed)
    start = datetime(2026, 9, 14, 9, 0, tzinfo=timezone.utc)

    if scenario is not None:
        if scenario == "random":
            data = random_noise(start, seed if seed is not None else random.randint(1, 100000))
        elif scenario in SCENARIOS:
            data = SCENARIOS[scenario](start)
        else:
            raise ValueError(f"Cenário desconhecido: {scenario}")
    elif level == "basic":
        choices = [scenario_normal, scenario_permission, scenario_privileged_service]
        scenario = random.choice(choices)
        data = scenario(start)
    elif level == "intermediate":
        choices = [scenario_permission, scenario_privileged_service, scenario_correlation, random_noise]
        scenario = random.choice(choices)
        if scenario is random_noise:
            data = scenario(start, random.randint(1, 100000))
        else:
            data = scenario(start)
    elif level == "challenge":
        choices = [scenario_correlation, scenario_ambiguous, random_noise]
        scenario = random.choice(choices)
        if scenario is random_noise:
            data = scenario(start, random.randint(1, 100000))
        else:
            data = scenario(start)
    else:
        raise ValueError(f"Nível desconhecido: {level}")

    out_dir.mkdir(parents=True, exist_ok=True)

    write_csv(
        out_dir / "processes.csv",
        ["timestamp", "pid", "ppid", "user", "stat", "cmd"],
        data["processes"],
    )
    write_csv(
        out_dir / "permissions.csv",
        ["path", "type", "owner", "group", "mode", "mtime"],
        data["permissions"],
    )

    with (out_dir / "services.txt").open("w", encoding="utf-8") as fh:
        fh.write("UNIT                         ACTIVE   USER      EXECSTART\n")
        for unit, active, user, execstart in data["services"]:
            fh.write(f"{unit:<28}{active:<9}{user:<10}{execstart}\n")

    with (out_dir / "journal.log").open("w", encoding="utf-8") as fh:
        for dt, message in sorted(data["logs"], key=lambda x: x[0]):
            fh.write(f"{dt.strftime('%b %d %H:%M:%S')} srv-app-01 {message}\n")

    metadata = {
        "dataset_type": "synthetic_training",
        "level": level,
        "scenario": data["kind"],
        "seed": seed,
        "generated_at": datetime.now().astimezone().isoformat(),
        "warning": "Dados fictícios para uso acadêmico; não representam um incidente real.",
    }
    (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")

    readme = [
        "ENDPOINT INVESTIGATOR - DATASET DE TREINAMENTO",
        "",
        "Este dataset é sintético e foi criado para testar ferramentas de investigação de endpoints Linux.",
        "Não representa um incidente real.",
        "",
        f"Nível: {level}",
        f"Cenário: {data['kind']}",
        "",
        "Arquivos:",
        "- processes.csv: snapshot de processos.",
        "- permissions.csv: metadados de arquivos e diretórios.",
        "- services.txt: serviços em execução.",
        "- journal.log: eventos de sistema.",
        "- metadata.json: metadados de geração.",
        "",
        "Orientação: não assuma que um único indicador é suficiente para concluir que houve comprometimento.",
        "Procure correlações e diferencie evidência, interpretação e hipótese.",
    ]
    if data["readme_extra"]:
        readme.extend(["", "Nota didática do cenário:", data["readme_extra"]])
    (out_dir / "README.txt").write_text("\n".join(readme) + "\n", encoding="utf-8")

    print(f"Dataset criado em: {out_dir}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Gera datasets sintéticos para Endpoint Investigator.")
    parser.add_argument("--level", choices=["basic", "intermediate", "challenge"], default="basic")
    parser.add_argument("--scenario", choices=SCENARIO_NAMES, default=None,
                        help="Gera um cenário nomeado e determinístico (ignora --level).")
    parser.add_argument("--output", default="./dataset", help="Diretório de saída.")
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--batch", type=int, default=1, help="Quantidade de datasets a gerar.")
    args = parser.parse_args()

    root = Path(args.output)
    if args.batch <= 1:
        make_dataset(args.level, args.seed, root, scenario=args.scenario)
        return

    root.mkdir(parents=True, exist_ok=True)
    for i in range(1, args.batch + 1):
        seed = (args.seed + i - 1) if args.seed is not None else random.randint(1, 10_000_000)
        make_dataset(args.level, seed, root / f"dataset-{i:03d}", scenario=args.scenario)


if __name__ == "__main__":
    main()
