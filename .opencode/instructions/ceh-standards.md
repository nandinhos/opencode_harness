# CLEARER Engineering Harness — Padrões (opencode)

## 1. Semântica de Evidência
Classifique todo fato técnico:
- **OBSERVED**: comprovado por arquivo lido, execução, teste, schema ou saída de ferramenta.
- **INFERRED**: conclusão razoável a partir de evidência observada, ainda não demonstrada.
- **UNKNOWN**: sem evidência suficiente no repositório/contexto.

`UNKNOWN` nunca vira `OBSERVED` silenciosamente. Proibido inventar arquivos, classes, métodos, endpoints, tabelas ou regras. Não encontrado ⇒ `UNKNOWN`/`NOT FOUND`.

## 2. Auditoria de Claims
- **SUPPORTED**: amparada por comando, linha de código ou teste.
- **PARTIALLY_SUPPORTED**: parcialmente demonstrada, com ressalvas.
- **UNSUPPORTED**: sem evidência.

## 3. Safety Gate por Ambiente (inegociável)
| Ambiente | Evidência | Política |
|---|---|---|
| `DEV`/`TEST` | branch `dev`/derivações, `APP_ENV=local/testing`, `.env` de dev | `ALLOW` com prontidão de backup local |
| `HOMOLOGACAO` | `staging`/`homolog`, `APP_ENV=staging`, `.env.staging` | `ASK` com 2 alertas: (1) impacto HML, (2) backup & rollback |
| `PRODUCAO` | `main`/`master`, `APP_ENV=production` | `DENY` incondicional |

**Catastróficos** (`rm -rf /`, `mkfs`, `dd of=/dev/`, fork bomb) são `DENY` em qualquer ambiente.
Casos: Banco (`DROP`, `TRUNCATE`, `migrate:fresh`, `db:wipe`), Git (`reset --hard`, `clean -f`, `push --force`), Filesystem (`rm -rf`), Infra (`terraform destroy`, `kubectl delete`).
Prefixo `rtk` é removido antes da avaliação — não burla o gate.

## 4. Topologia de Branches
- **Classic**: `dev → main`.
- **Enterprise**: `dev → staging → main`.
Derivações partem sempre de `dev` (`dev/[slug]`, `feat/*`, `fix/*`).

## 5. Craftsmanship & Ponytail Mode
*Entender muito, construir pouco, entregar certo.* Escada de decisão antes de escrever código (pare no primeiro SIM):
1. Precisa mesmo existir? (YAGNI)
2. Já existe na base? Reutilize.
3. A stdlib resolve? Use-a.
4. Existe API nativa da plataforma? Priorize.
5. Uma intervenção cirúrgica resolve? Menor diff funcional.

Princípios: código idiomático; **tipagem estrita** (proibido `any`/`mixed` sem narrowing na borda); resiliência (nulos, vazios, timeouts, exceções); blast radius mínimo; contratos públicos preservados; nada de ruído cosmético.

## 6. Root-Cause First
`Sintoma → Reprodução → Observação → Hipótese → Causa Raiz → Teste de Regressão → Correção Mínima`. Nunca patch cego para esconder sintoma.

## 7. Testes
A palavra "testado" exige execução real. Registre `COMMAND`, `EXIT CODE`, `RESULT`. Cubra happy path, unhappy path, nulos, vazios e limites. **Proibido fake pass** e mascaramento; se não executável, declare `NOT RUN` com motivo. Em falha, 1 iteração de auto-reparo guiada por stack trace; persistindo, handoff.

## 8. Segurança
Entrada não confiável por padrão. Autenticação/permissões/sessões/criptografia ⇒ risco automaticamente `HIGH`. Inspecione injeções (SQL parametrizado, sem shell strings dinâmicas, escape de saída), autorização no backend e proteção de segredos (nunca comitar credenciais).

## 9. Git Safety
Inspecione `git status --short` e `git branch --show-current` antes de alterar. Nunca descarte trabalho alheio sem autorização. Revise com `git diff --stat` e `git diff --check` antes de finalizar.

## 10. Ciência de Tokens
- **AST first**: se houver Graphify (`graphify-out/graph.json`/MCP), priorize consultas relacionais.
- **Fallback**: `grep` + leitura fatiada; proibido dump de arquivos inteiros sem necessidade.
- **RTK**: se `rtk` estiver no PATH, prefixe comandos verbosos (`rtk git status`, `rtk pytest`); escape hatch via `rtk proxy`.
- **Higiene**: mantenha outputs pesados fora da janela de contexto.
