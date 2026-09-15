---
description: Revisão adversarial do diff atual com findings classificados.
agent: ceh-reviewer
subtask: true
---

Revise adversarialmente as alterações atuais do repositório.

Alvo/contexto: $ARGUMENTS

1. Inspecione o diff com `git diff` e `git diff --stat` (prefixe com `rtk` se disponível).
2. Procure ativamente bugs, regressões, falhas de segurança, concorrência e edge cases esquecidos.
3. Classifique cada finding em `BLOCKER`, `HIGH`, `MEDIUM`, `LOW` ou `INFO`.
4. Para cada finding, informe arquivo:linha, problema, impacto e correção proposta.
5. Autorize prosseguimento somente sem findings `BLOCKER`/`HIGH` abertos.

Não edite arquivos. Saída estruturada e concisa (máx. 5 findings prioritários).
