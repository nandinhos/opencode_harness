---
description: Exibe o perfil CEH resolvido, o ambiente detectado e o estado do harness.
agent: ceh-orchestrator
---

Inspecione o harness CEH ativo e reporte, sem editar arquivos:

1. Leia `.opencode/ceh.profile.json` e resuma o perfil de alto nível (risk dial, tiers de ambiente, agentes habilitados, economia de tokens).
2. Detecte o ambiente atual (`development`/`staging`/`production`) usando variáveis (`CEH_ENV`, `APP_ENV`, `NODE_ENV`, `ENVIRONMENT`, `ENV`, `STAGE`), arquivos `.env*` e a branch Git — informe a **evidência** de cada conclusão.
3. Liste a topologia de branches (classic/enterprise) e a stack detectada.
4. Liste os agentes CEH e comandos disponíveis.

Saída em `OBSERVED`, no formato do Response Contract, com no máximo 5 pendências. Não altere nada.
