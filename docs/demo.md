# Roteiro da demonstração — 06/10

Tudo roda da raiz do repositório. Tempo total: ~6 min para a metade de análise.

## Antes de começar

```bash
for s in correlation tampered_after_login privileged_service ambiguous \
         user_to_root missing_evidence permission; do
  python3 generate_dataset.py --scenario $s --output training/$s
done
python3 -m unittest discover tests        # 49 testes, OK
```

## Parte 1 — o que a ferramenta vê (Galazzi)

```bash
python3 -m investigator --dataset training/correlation --dump-snapshot --out reports/correlation
```

Mostrar em `reports/correlation/snapshot.json`: `ancestry`, `unit_method`,
`nonroot_writable` + `nonroot_reason`, `timeline`, `gaps`.

## Parte 2 — o que a ferramenta conclui (Sardou)

**1. O caso central: evidência → interpretação → hipótese → evidência ausente**

```bash
python3 -m investigator --dataset training/correlation --out reports/correlation; echo "exit=$?"
```

Apontar: a cadeia `serviço → root → PID → script → 0777`; cada linha de evidência
com sua origem; "Isso NÃO prova exploração"; o `mtime` é *anterior* ao login do
aluno; `exit=1`. O SUID `report-sync` sai INCONCLUSIVO, não RISCO.

**2. O mesmo serviço, agora com a sequência temporal**

```bash
python3 -m investigator --dataset training/tampered_after_login --out reports/tampered | sed -n '/^ACHADOS/,/^CONCLUSÃO/p'
```

Apontar: login → modificação → início do serviço, dito como coincidência temporal.

**3. Root não é o gatilho**

```bash
python3 -m investigator --dataset training/privileged_service --out reports/priv; echo "exit=$?"
```

Apontar: mesmo serviço root, script 0700 → "Verificações sem achado"; o `curl`
sai INCONCLUSIVO com o log do próprio serviço como contexto; `exit=0`.

**4. Quando a ferramenta diz "não sei"**

```bash
python3 -m investigator --dataset training/missing_evidence --out reports/missing | sed -n '/^ACHADOS/,/^CONCLUSÃO/p'
python3 -m investigator --dataset training/ambiguous --out reports/ambiguous | sed -n '/^ACHADOS/,/^CONCLUSÃO/p'
```

**5. Contexto de execução (C2)**

```bash
python3 -m investigator --dataset training/user_to_root --out reports/u2r | sed -n '/^ACHADOS/,/^CONCLUSÃO/p'
```

Apontar a cadeia `init → sshd → sshd(aluno) → bash(aluno) → bash(root)`.

**6. Ao vivo (VM Kali, com snapshot da VM tirado antes)**

```bash
sudo bash lab/setup_lab.sh
sudo python3 -m investigator --live --out reports/live; echo "exit=$?"
sudo bash lab/teardown_lab.sh
```

Esperado: `ei-lab-backup` RISCO · `ei-lab-safe` em verificações sem achado ·
`ei-lab-id` SUID INCONCLUSIVO · porta 8081 INCONCLUSIVO.
Plano B se a VM falhar: `python3 -m investigator --live --out reports/live` sem
sudo, mostrando a seção de lacunas.

## Perguntas prováveis

- *Por que o serviço root com 0700 não é achado?* Porque o risco está na
  combinação identidade + recurso + quem pode modificá-lo, e aqui só root modifica.
- *Como sabem que o aluno alterou o script?* Não sabemos; o achado diz isso em
  "evidência ausente" (auditd, hash) e o `mtime` pode ser forjado.
- *O que é "confiança alta"?* Três ou mais tipos de fonte independentes
  sustentando a relação observada — não a certeza da hipótese.
