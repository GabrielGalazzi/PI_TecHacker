#!/usr/bin/env bash
#
# teardown_lab.sh — remove tudo o que setup_lab.sh cria.
#
# APENAS para a VM Kali. Roda como root. É idempotente: pode ser executado
# mesmo que parte do laboratório já tenha sido removida.

set -uo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "Este script precisa de root (use: sudo bash lab/teardown_lab.sh)." >&2
    exit 1
fi

echo "[*] Parando e desabilitando os serviços de laboratório"
for unit in ei-lab-backup.service ei-lab-safe.service; do
    systemctl disable --now "${unit}" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/${unit}"
done
systemctl daemon-reload || true

echo "[*] Encerrando o http.server da porta 8081"
if [[ -f /tmp/ei-lab/http.pid ]]; then
    kill "$(cat /tmp/ei-lab/http.pid)" >/dev/null 2>&1 || true
fi
# rede de segurança: mata qualquer http.server na 8081 que tenha sobrado
pkill -f "http.server 8081" >/dev/null 2>&1 || true

echo "[*] Removendo arquivos e SUID de laboratório"
rm -f /usr/local/bin/ei-lab-id
rm -rf /opt/ei-lab /opt/ei-lab-safe /tmp/ei-lab

echo "[ok] Laboratório removido."
