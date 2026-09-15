---
description: Audita claims contra evidências e emite o relatório final.
agent: ceh-evidence-auditor
subtask: true
---

Audite as alegações da tarefa atual confrontando cada claim com evidência verificável.

Escopo: $ARGUMENTS

1. Liste as claims (ex.: "testes passaram", "sem regressão", "bug corrigido", "seguro contra injeção").
2. Verifique cada uma com comando/arquivo/teste; registre `COMMAND`, `EXIT CODE` e resultado.
3. Classifique cada claim como `SUPPORTED`, `PARTIALLY_SUPPORTED` ou `UNSUPPORTED`.
4. Rejeite afirmações sem evidência e marque o que for `UNKNOWN`/`NOT RUN`.
5. Emita o Relatório Final de Evidências (Response Contract) com Confiança `HIGH`/`MEDIUM`/`LOW`.

Não edite arquivos.
