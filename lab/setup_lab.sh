#!/usr/bin/env bash
#
# setup_lab.sh — monta o laboratório controlado do Endpoint Investigator.
#
# APENAS para a VM Kali (ou VM descartável). Roda como root. Cria casos
# determinísticos para a demonstração do modo --live:
#
#   ei-lab-backup.service  (User=root) -> /opt/ei-lab/backup.sh       modo 0777  [POSITIVO]
#   ei-lab-safe.service    (User=root) -> /opt/ei-lab-safe/agent.sh   modo 0700  [CONTROLE]
#   /usr/local/bin/ei-lab-id  = cópia de /usr/bin/id com modo 4755    [SUID não-padrão]
#   http.server :8081 como usuário kali a partir de /tmp/ei-lab       [porta sem serviço]
#
# Use lab/teardown_lab.sh para remover tudo o que este script cria.

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "Este script precisa de root (use: sudo bash lab/setup_lab.sh)." >&2
    exit 1
fi

LAB_USER="${LAB_USER:-kali}"

echo "[*] Caso POSITIVO: ei-lab-backup.service com script 0777"
mkdir -p /opt/ei-lab
cat > /opt/ei-lab/backup.sh <<'EOF'
#!/bin/bash
# Script de laboratório (fictício). Apenas um laço de espera.
while true; do
    sleep 3600
done
EOF
chmod 0777 /opt/ei-lab/backup.sh

cat > /etc/systemd/system/ei-lab-backup.service <<'EOF'
[Unit]
Description=EI Lab Backup Agent (fictitious, insecure on purpose)

[Service]
Type=simple
User=root
ExecStart=/bin/bash /opt/ei-lab/backup.sh
Restart=no

[Install]
WantedBy=multi-user.target
EOF

echo "[*] Caso CONTROLE: ei-lab-safe.service com script 0700 (NÃO deve ser sinalizado)"
mkdir -p /opt/ei-lab-safe
cat > /opt/ei-lab-safe/agent.sh <<'EOF'
#!/bin/bash
# Script de laboratório (fictício), com permissão restrita.
while true; do
    sleep 3600
done
EOF
chmod 0700 /opt/ei-lab-safe/agent.sh

cat > /etc/systemd/system/ei-lab-safe.service <<'EOF'
[Unit]
Description=EI Lab Safe Agent (fictitious, restricted)

[Service]
Type=simple
User=root
ExecStart=/bin/bash /opt/ei-lab-safe/agent.sh
Restart=no

[Install]
WantedBy=multi-user.target
EOF

echo "[*] SUID não-padrão: /usr/local/bin/ei-lab-id (cópia de id com 4755)"
cp /usr/bin/id /usr/local/bin/ei-lab-id
chmod 4755 /usr/local/bin/ei-lab-id

echo "[*] Ativando os serviços de laboratório"
systemctl daemon-reload
systemctl enable --now ei-lab-backup.service
systemctl enable --now ei-lab-safe.service

echo "[*] Porta 8081 sem serviço: http.server como usuário ${LAB_USER}"
mkdir -p /tmp/ei-lab
chown "${LAB_USER}:${LAB_USER}" /tmp/ei-lab 2>/dev/null || true
if id "${LAB_USER}" >/dev/null 2>&1; then
    sudo -u "${LAB_USER}" bash -c \
        'cd /tmp/ei-lab && nohup python3 -m http.server 8081 >/tmp/ei-lab/http.log 2>&1 & echo $! > /tmp/ei-lab/http.pid'
    echo "    http.server iniciado (pid $(cat /tmp/ei-lab/http.pid 2>/dev/null || echo '?'))"
else
    echo "    [aviso] usuário ${LAB_USER} não existe; pulei o http.server. Defina LAB_USER=<usuário>." >&2
fi

echo "[ok] Laboratório montado. Rode: sudo python3 -m investigator --live --out reports/live"
