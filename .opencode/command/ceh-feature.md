---
description: Ciclo CLEARER end-to-end para uma nova feature (turno único em MEDIUM).
agent: ceh-orchestrator
---

Feature a implementar: $ARGUMENTS

Conduza o CLEARER Engineering Harness de ponta a ponta:

1. **Concrete Goal**: objetivo, ambiente (`DEV`/`HOMOLOGACAO`/`PRODUCAO`), critérios de aceite e condição de parada.
2. **Load Context**: inspecione arquivos alvo, testes e convenções (inspect before edit). Não invente símbolos.
3. **Boundaries**: delimite blast radius mínimo e contratos preservados.
4. **Risk Dial**: classifique (LOW/MEDIUM/HIGH). Em HIGH, delegue aos subagentes e peça checkpoint humano.
5. **Implement**: menor diff funcional, tipagem estrita, sem refatoração oportunista.
6. **Test**: execute a suíte real e registre `COMMAND`, `EXIT CODE`, `RESULT`.
7. **Review/Audit**: revise o diff de forma adversarial e confronte claims com evidências.
8. **Report**: emita o Response Contract com classificação `OBSERVED`/`INFERRED`/`UNKNOWN`.
