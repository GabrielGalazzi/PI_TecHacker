# Documento Técnico — Endpoint Investigator

> Documento de até 4 páginas (exportar para PDF na entrega). As seções abaixo
> marcadas *(Sardou)* são preenchidas na Parte 2.

## Problema

O trabalho pede uma ferramenta que **colete, relacione e interprete** o estado de
um endpoint GNU/Linux cobrindo **processos, permissões e serviços**, com pelo
menos duas correlações, e que separe **evidência, interpretação, hipótese e
evidência ausente** — dizendo com clareza quando a evidência é insuficiente.

O risco pedagógico central é o raciocínio simplista do tipo "serviço root =
vulnerabilidade" ou "conexão externa = C2". A ferramenta precisa, portanto,
tratar cada indicador como *contexto*, e só concluir risco quando várias fontes
independentes se sustentam mutuamente. A coleta (esta metade) existe para dar à
análise uma base de fatos estruturada, rastreável e honesta sobre suas lacunas.

## Arquitetura

O pipeline é linear e tem **um módulo por etapa** (ver o diagrama no README).
Duas entradas distintas — um dataset no formato do professor e a máquina ao vivo —
convergem para **um único `Snapshot` normalizado**. A análise (correlação,
evidências, relatório) lê sempre esse mesmo contrato, sem saber de onde os dados
vieram.

O `Snapshot` reúne:

- `processes{pid→Process}` com identidade (UID real/efetivo no live), estado,
  linha de comando, executável, script (quando o executável é interpretador),
  **cadeia de ancestralidade** (`ancestry`) e a unidade systemd mapeada;
- `services{unit→Service}` com usuário, `ExecStart`, `MainPID`, arquivo de unidade
  e os caminhos referenciados;
- `files{path→FileInfo}` com dono/grupo/modo, flags derivadas (world/group-writable,
  SUID, SGID) e a conclusão `nonroot_writable` com justificativa;
- `logs[]` estruturados e uma **linha do tempo** tipada e ordenada (`timeline`);
- `sockets[]` e `cron[]` (extras do modo live);
- `gaps[]` — tudo o que **não** pôde ser coletado.

Cada fato carrega `src` (proveniência: `processes.csv:5`, `/proc/2417/status`, …),
o que permite que toda conclusão da análise aponte para a observação que a gerou.

## Decisões técnicas

- **Python 3.10+, apenas biblioteca padrão.** O Kali já traz Python; não há o que
  instalar, e o gerador do professor também é Python.
- **Um snapshot sob demanda, sem agente.** O enunciado permite; simplifica.
- **Sem LLM dentro da ferramenta.** Toda a análise é baseada em regras e
  rastreável, evitando o anti-padrão "DADOS → LLM". O uso de IA no
  desenvolvimento é documentado à parte.
- **Comparação temporal em wall-clock *naive*.** Os CSVs anexam `-03:00` a
  horários UTC; o journal traz o mesmo wall-clock sem offset. Normalizamos tudo
  para wall-clock sem fuso, de modo que `mtime`, logins e reinícios sejam
  diretamente comparáveis (essencial para a reconstrução temporal C4).
- **`nonroot_writable` como conceito central de permissão.** Um arquivo conta
  como gravável por não-root quando: `o+w`; ou o grupo tem escrita e não é `root`
  (no live checa-se a participação via `grp`/`pwd`; no dataset assume-se que o
  grupo pode conter não-root, e isso é dito na justificativa); ou o dono não é
  root; ou **qualquer diretório-pai** satisfaz uma dessas condições (o arquivo
  pode ser substituído). Usa-se `None` quando não há dados de permissão.
- **Mapeamento processo→serviço por métodos em ordem**, registrando qual casou:
  cgroup, MainPID (live), `cmd == ExecStart` com ppid 1, mesmo script, herança de
  ancestral mapeado e, por fim, nome-base da unidade == basename do executável
  (fraco). Registrar o método torna a força da associação auditável.
- **Coleta de arquivos por contexto, não por varredura.** No live só são
  inspecionados os caminhos referenciados por serviços, processos e cron, cada um
  com todos os diretórios-pai até `/`. Isso mantém a coleta barata e relevante.
- **Correção no gerador do professor.** `random_noise()` reaproveitava o dict já
  construído por `scenario_normal()` e o reenviava a `build()`, quebrando com
  `ValueError: too many values to unpack` em `--level intermediate/challenge`.
  Passou a partir dos dados crus (tuplas). Detalhes em `report_galazzi.md`.

## Limitações da coleta

A ferramenta **declara** estas limitações em vez de escondê-las (elas aparecem em
`gaps` e no relatório):

- **Snapshot único.** Processos efêmeros não são vistos; logs podem ter sido
  rotacionados ou limpos; `mtime` pode ser forjado (`touch`).
- **Modo dataset.**
  - Sem UID/EUID nem participação em grupos.
  - Sem crontabs/timers.
  - Horários sem ano e fuso ambíguo (tratados via wall-clock naive).
  - O mapeamento processo↔serviço depende de casamento de comando.
- **Modo live.** Requer root para visão completa; cada permissão ou log que não
  pôde ser lido vira uma lacuna explícita. Sem root, a visibilidade é parcial e
  isso é declarado.

---

## Estratégia de investigação

_(seção de Sardou — Parte 2)_

## Principais correlações

_(seção de Sardou — Parte 2)_

## Uso de IA

_(seção de Sardou — Parte 2; resumo: IA foi usada como apoio de planejamento e
codificação; a ferramenta em si não usa LLM.)_

## Limitações da análise

_(seção de Sardou — Parte 2)_
