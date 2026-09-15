---
description: Correção de bug root-cause-first com teste de regressão obrigatório.
agent: ceh-orchestrator
---

Bug a corrigir: $ARGUMENTS

Siga o protocolo de correção do CEH (nada de patch cego):

1. **Sintoma → Reprodução**: reproduza o defeito e registre a evidência (`OBSERVED`).
2. **Hipóteses falsificáveis**: liste hipóteses e o teste que falsifica cada uma.
3. **Causa Raiz**: comprove a causa raiz antes de corrigir.
4. **Correção Mínima**: menor diff funcional, sem refatoração fora do escopo.
5. **Teste de Regressão**: adicione um teste automatizado que falha antes e passa depois (Detector).
6. **Review/Audit**: revisão adversarial do diff + confronto `CLAIM ↔ EVIDENCE`.
7. **Report**: Response Contract com evidência da reprodução antes/depois.
