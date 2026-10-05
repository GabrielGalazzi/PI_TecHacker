# Notas do apresentador — Endpoint Investigator

Notas de cada slide de `apresentacao.pptx` / `apresentacao.pdf` (06/10).

## 1. Endpoint Investigator

Apresentação do grupo. Endpoint Investigator: ferramenta de investigação para Linux que coleta processos, permissões e serviços, cruza essas fontes e entrega achados que separam evidência, interpretação, hipótese e evidência ausente. À direita, a saída real da ferramenta no cenário correlation.

## 2. Evidência isolada não é incidente

O enunciado não quer o maior número de vulnerabilidades, quer raciocínio. Por isso nenhum indicador isolado vira achado: o risco está na combinação identidade privilegiada + recurso usado + capacidade de modificação, como no exemplo do enunciado (serviço → root → script → gravável). RISCO exige pelo menos dois tipos de fonte; quando falta dado, a ferramenta diz INCONCLUSIVO.

## 3. Arquitetura: um Snapshot, um pipeline

O fluxo segue exatamente o fluxo de referência do enunciado, com um módulo por etapa. Duas entradas — o dataset no formato do professor e a coleta ao vivo via /proc, systemctl show, os.lstat, journalctl, ss e cron — convergem para o mesmo Snapshot normalizado. Python 3.10+ só com biblioteca padrão. Código de saída: 0 sem RISCO, 1 com RISCO, 2 erro.

## 4. Processos, permissões e serviços

As três dimensões obrigatórias. Processos: não reproduzimos o ps — construímos a cadeia de ancestralidade com identidade em cada elo e descobrimos o script real executado pelo interpretador. Permissões: o conceito central é nonroot_writable, que considera também o diretório-pai (o arquivo pode ser substituído). Serviços: o vínculo processo↔serviço é feito por métodos em ordem de força, e o método usado é registrado.

## 5. Quatro correlações entre fontes

O enunciado pede no mínimo duas correlações; implementamos as quatro sugeridas, em investigator/correlate.py. Nenhuma conclui a partir de um indicador isolado. C2 no modo live também aponta porta em escuta sem serviço dedicado e UID real diferente do efetivo. C4 não gera RISCO sozinha: ela acrescenta a reconstrução temporal aos achados de C1 (C1+C4).

## 6. Da cadeia ao achado: C1 + C4

Exemplo real. C1 monta a cadeia serviço → identidade → processo → arquivo → quem pode alterar. C4 coloca no tempo: o aluno faz login às 09:01:40, o script muda às 09:03:20 e o serviço root inicia às 09:05:00 — ou seja, o conteúdo atual pode já ter rodado como root. No cenário correlation o mtime é anterior ao login, e a ferramenta diz que não há indício de modificação durante a sessão.

## 7. Anatomia de um achado

Este é o critério de distinção entre evidência, interpretação e hipótese. Os quatro campos são separados na própria estrutura de dados (Finding), não só no texto. Cada linha de evidência começa pela origem: a linha do arquivo do dataset ou a interface do sistema consultada. A evidência ausente diz o que confirmaria ou rejeitaria a hipótese — aqui, hash do script e auditd.

## 8. Conclusões e confiança

Severidade é o impacto se a hipótese for verdadeira; confiança é quantos tipos de fonte independentes sustentam a relação observada — não a certeza da hipótese. RISCO exige duas fontes; com uma só, o achado é rebaixado para CONFIG_INADEQUADA ou INCONCLUSIVO e a fonte que falta entra em evidência ausente. Ocorrências com a mesma causa viram um único achado.

## 9. Resultados nos 9 cenários

Os 9 cenários nomeados do gerador do professor (com --scenario, que adicionamos, além da correção do random_noise). Os 4 cenários com relação de privilégio saem RISCO; os outros 5 não geram RISCO nenhum — inclusive privileged_service, em que o serviço é root mas só root altera o script. Em privileged_service o curl sai INCONCLUSIVO com o log do próprio serviço como contexto. A suíte tests/ tem 51 testes, todos passando.

## 10. Demonstração

Roteiro em docs/demo.md. Antes: gerar os 7 cenários e rodar a suíte de testes. Parte 1 (Galazzi): --dump-snapshot no cenário correlation mostrando ancestry, unit_method, nonroot_writable, timeline e gaps. Parte 2 (Sardou): os 5 casos à esquerda. Ao vivo, com snapshot da VM tirado antes: setup_lab cria um caso positivo, um controle e dois inconclusivos; teardown_lab remove tudo.

## 11. Decisões técnicas e uso de IA

Decisões principais. O wall-clock sem fuso resolve um detalhe do dataset: os CSVs anexam -03:00 e o journal não, e sem normalizar não dá para comparar mtime com login. Corrigimos um bug do gerador do professor (random_noise reaproveitava o dict já construído) — detalhes em report_galazzi.md. IA foi usada no desenvolvimento; a ferramenta em si não tem etapa de LLM, atendendo à exigência do enunciado.

## 12. Limitações e escopo

O enunciado pede que cada grupo indique onde a ferramenta pode errar. Falsos positivos e negativos estão documentados no README e no documento técnico, e as lacunas de cada execução aparecem no próprio relatório. Uma boa ferramenta de investigação reconhece quando não há evidência suficiente.

## 13. Observar, correlacionar, explicar — e dizer quando não há evidência suficiente

Fechamento. Perguntas prováveis (docs/demo.md): por que serviço root com 0700 não é achado (só root modifica o recurso); como sabem que o aluno alterou o script (não sabemos — está em evidência ausente, e o mtime pode ser forjado); o que é confiança alta (três ou mais tipos de fonte independentes sustentando a relação observada).
