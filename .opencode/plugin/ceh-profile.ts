import type { Plugin } from "@opencode-ai/plugin"
import { execFileSync } from "node:child_process"
import { existsSync, readFileSync, statSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

type Tier = "allow" | "ask" | "deny"
type EnvName = "development" | "staging" | "production"
type RiskLevel = "LOW" | "MEDIUM" | "HIGH"

type Profile = {
  profile: string
  riskDial: { default: RiskLevel; allowEscalation: boolean; checkpointOnHigh: boolean }
  environment: { mode: "auto" | EnvName; topology: "classic" | "enterprise"; tiers: Record<EnvName, Tier> }
  safety: { catastrophic: Tier; enforcePermissionHook: boolean; hardBlockBeforeExecution: boolean }
  stack: { autoDetect: boolean; language: string; testRunner: string; linter: string; strictTyping: boolean }
  craftsmanship: { ponytail: boolean; blastRadius: string; rootCauseFirst: boolean; conventionalCommits: boolean }
  evidence: { required: boolean; classes: string[]; forbidUnsupportedClaims: boolean; responseContract: boolean }
  tokenEconomy: { astFirst: boolean; shellCompression: string; rtkPrefixes: string[] }
  agents: Record<string, boolean>
  presentation: { noPreamble: boolean; maxListItems: number; endWithNextStep: boolean }
}

type Verdict = { decision: Tier; reason: string; env: EnvName; useCase: string }

const DEFAULT_PROFILE: Profile = {
  profile: "staff",
  riskDial: { default: "MEDIUM", allowEscalation: true, checkpointOnHigh: true },
  environment: {
    mode: "auto",
    topology: "classic",
    tiers: { development: "allow", staging: "ask", production: "deny" },
  },
  safety: { catastrophic: "deny", enforcePermissionHook: true, hardBlockBeforeExecution: true },
  stack: { autoDetect: true, language: "auto", testRunner: "auto", linter: "auto", strictTyping: true },
  craftsmanship: { ponytail: true, blastRadius: "minimal", rootCauseFirst: true, conventionalCommits: true },
  evidence: {
    required: true,
    classes: ["OBSERVED", "INFERRED", "UNKNOWN"],
    forbidUnsupportedClaims: true,
    responseContract: true,
  },
  tokenEconomy: {
    astFirst: true,
    shellCompression: "auto",
    rtkPrefixes: ["git", "npm", "pnpm", "yarn", "pytest", "cargo", "docker", "ruff", "php", "composer"],
  },
  agents: {
    orchestrator: true,
    investigator: true,
    architect: true,
    implementer: true,
    testEngineer: true,
    reviewer: true,
    evidenceAuditor: true,
  },
  presentation: { noPreamble: true, maxListItems: 5, endWithNextStep: true },
}

const ENV_VARS = ["CEH_ENV", "APP_ENV", "NODE_ENV", "ENVIRONMENT", "ENV", "STAGE"]

const CATASTROPHIC: Array<[RegExp, string]> = [
  [/\brm\s+-[rRfF]*[rR][rRfF]*\s+\/(?:\s|$)/, "recursive deletion of root '/'"],
  [/\brm\s+-[rRfF]*[rR][rRfF]*\s+~(?:\s|\/|$)/, "recursive deletion of home '~'"],
  [/\brm\s+-[rRfF]*[rR][rRfF]*\s+\.\.(?:\s|\/|$)/, "recursive deletion of parent '..'"],
  [/\brm\s+-[rRfF]*[rR][rRfF]*\s+\*(?:\s|$)/, "blind wildcard recursive deletion"],
  [/\bmkfs\b/, "filesystem formatting"],
  [/\bdd\s+if=.*of=\/dev\//, "direct disk write via dd"],
  [/:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, "fork bomb"],
  [/\bgcloud\s+projects\s+delete\b/, "GCP project deletion"],
  [/\bformat\s+[a-z]:/i, "Windows disk format"],
  [/\bdiskpart\b/i, "diskpart destructive partitioning"],
  [/\bRemove-Item\b[^\n]*-Recurse[^\n]*\bC:\\\\?(?:\s|$)/i, "recursive deletion of C: drive"],
  [/\bFormat-Volume\b/i, "Format-Volume destructive format"],
  [/\bClear-Disk\b/i, "Clear-Disk destructive wipe"],
]

const SAFE_DEV: RegExp[] = [
  /\brm\s+-[rRfF]+\s+(?:\/tmp\/|tmp\/|\.tmp\/|scratch\/|\.cache\/|dist\/|build\/|coverage\/|node_modules\/)/,
  /\brm\s+-[rRfF]*[fF][rRfF]*\s+[\w./-]+\.[a-zA-Z0-9]+(?:\s|$)/,
  /\bgit\s+(?:checkout|restore)\s+(?![.\-]\s*$)[\w./-]+(?:\s|$)/,
]

const DESTRUCTIVE: Array<[RegExp, string, string]> = [
  [/\bDROP\s+DATABASE\b/i, "DROP DATABASE", "DATABASE"],
  [/\bDROP\s+SCHEMA\b/i, "DROP SCHEMA", "DATABASE"],
  [/\bDROP\s+TABLE\b/i, "DROP TABLE", "DATABASE"],
  [/\bDROP\s+VIEW\b/i, "DROP VIEW", "DATABASE"],
  [/\bTRUNCATE(?:\s+TABLE)?\b/i, "TRUNCATE", "DATABASE"],
  [/\bDELETE\s+FROM\s+\w+\s*(?:;\s*$|$)/i, "unconditional DELETE", "DATABASE"],
  [/\bDELETE\s+FROM\s+\w+\s+WHERE\s+1\s*=\s*1/i, "DELETE WHERE 1=1", "DATABASE"],
  [/\b(?:php\s+)?artisan\s+migrate:(?:fresh|reset)\b/i, "migrate:fresh/reset", "DATABASE"],
  [/\b(?:php\s+)?artisan\s+db:wipe\b/i, "db:wipe", "DATABASE"],
  [/\bgit\s+reset\s+--hard\b/i, "git reset --hard", "GIT_HISTORY"],
  [/\bgit\s+clean\s+-[a-zA-Z]*f/i, "git clean -f", "GIT_HISTORY"],
  [/\bgit\s+restore\s+(?:\.|\s+--staged\s+\.)/i, "git restore .", "GIT_HISTORY"],
  [/\bgit\s+checkout\s+--\s+\.\b/i, "git checkout -- .", "GIT_HISTORY"],
  [/\bgit\s+checkout\s+\.\b/i, "git checkout .", "GIT_HISTORY"],
  [/\bgit\s+branch\s+-[dD]\b/i, "git branch deletion", "GIT_HISTORY"],
  [/\bgit\s+push\s+.*(?:--force|-f)\b/i, "git push --force", "GIT_HISTORY"],
  [/\bgit\s+push\s+.*\+[\w/-]+/i, "git push refspec '+'", "GIT_HISTORY"],
  [/\brm\s+-[rRfF]+/i, "recursive/forced deletion", "FILESYSTEM"],
  [/\bterraform\s+destroy\b/i, "terraform destroy", "INFRASTRUCTURE"],
  [/\bkubectl\s+delete\s+(?:namespace|ns|deployment|statefulset|svc|all)\b/i, "kubectl delete", "INFRASTRUCTURE"],
  [/\bdocker\s+system\s+prune\s+-a\b/i, "docker system prune -a", "INFRASTRUCTURE"],
  [/\bgsutil\s+rm\s+-r\b/i, "gsutil rm -r", "INFRASTRUCTURE"],
  [/\b(?:npm|pnpm|yarn)\s+publish\b/i, "package publish", "PACKAGE"],
  [/\bRemove-Item\b[^\n]*-Recurse[^\n]*-Force/i, "Remove-Item -Recurse -Force", "FILESYSTEM"],
  [/\bRemove-Item\b[^\n]*-Recurse/i, "Remove-Item -Recurse", "FILESYSTEM"],
  [/\b(?:rmdir|rd)\s+\/s\b/i, "rmdir /s", "FILESYSTEM"],
  [/\bdel\b[^\n]*\/[fsq]{1,3}\b/i, "del with /f /s /q", "FILESYSTEM"],
  [/\bFormat-Volume\b/i, "Format-Volume", "INFRASTRUCTURE"],
  [/\bClear-Disk\b/i, "Clear-Disk", "INFRASTRUCTURE"],
]

const DESTRUCTIVE_GLOBS = [
  "rm *",
  "*DROP TABLE*",
  "*DROP DATABASE*",
  "*DROP SCHEMA*",
  "*TRUNCATE*",
  "*DELETE FROM*",
  "*migrate:fresh*",
  "*migrate:reset*",
  "*db:wipe*",
  "git reset --hard*",
  "git clean *",
  "git restore .*",
  "git checkout .*",
  "git push*--force*",
  "git push* -f*",
  "git branch -d*",
  "git branch -D*",
  "*terraform destroy*",
  "*kubectl delete*",
  "*docker system prune*",
  "*gsutil rm -r*",
  "*npm publish*",
  "*pnpm publish*",
  "*yarn publish*",
  "*Remove-Item*-Recurse*",
  "*rmdir /s*",
  "*del /f*",
  "*del /s*",
  "*Format-Volume*",
  "*Clear-Disk*",
]

const CATASTROPHIC_GLOBS = [
  "rm -rf /",
  "rm -fr /",
  "rm -rf /*",
  "rm -rf ~*",
  "rm -rf ..*",
  "rm -rf *",
  "*mkfs*",
  "*dd if=*of=/dev/*",
  "*gcloud projects delete*",
  "*diskpart*",
  "*format c:*",
  "*Format-Volume*",
  "*Clear-Disk*",
]

const AGENT_NAMES: Record<string, string> = {
  orchestrator: "ceh-orchestrator",
  investigator: "ceh-investigator",
  architect: "ceh-architect",
  implementer: "ceh-implementer",
  testEngineer: "ceh-test-engineer",
  reviewer: "ceh-reviewer",
  evidenceAuditor: "ceh-evidence-auditor",
}

const READ_ONLY_AGENTS = new Set(["ceh-investigator", "ceh-architect"])

function mergeProfile(base: Profile, override: Partial<Profile>): Profile {
  return {
    ...base,
    ...override,
    riskDial: { ...base.riskDial, ...(override.riskDial ?? {}) },
    environment: {
      ...base.environment,
      ...(override.environment ?? {}),
      tiers: { ...base.environment.tiers, ...(override.environment?.tiers ?? {}) },
    },
    safety: { ...base.safety, ...(override.safety ?? {}) },
    stack: { ...base.stack, ...(override.stack ?? {}) },
    craftsmanship: { ...base.craftsmanship, ...(override.craftsmanship ?? {}) },
    evidence: { ...base.evidence, ...(override.evidence ?? {}) },
    tokenEconomy: { ...base.tokenEconomy, ...(override.tokenEconomy ?? {}) },
    agents: { ...base.agents, ...(override.agents ?? {}) },
    presentation: { ...base.presentation, ...(override.presentation ?? {}) },
  }
}

function readProfile(root: string): Profile {
  const candidates = [join(root, ".opencode", "ceh.profile.json"), join(root, ".opencode", "opencode.profile.json")]
  for (const file of candidates) {
    if (!existsSync(file)) continue
    try {
      const parsed = JSON.parse(readFileSync(file, "utf8")) as Partial<Profile>
      return mergeProfile(DEFAULT_PROFILE, parsed)
    } catch {
      return DEFAULT_PROFILE
    }
  }
  return DEFAULT_PROFILE
}

function normalizeEnv(value: string): EnvName {
  const v = value.trim().toLowerCase()
  if (/(prod|production|prd|live)/.test(v)) return "production"
  if (/(stage|staging|homolog|homologacao|uat|qa)/.test(v)) return "staging"
  return "development"
}

function readEnvFile(file: string): EnvName | null {
  try {
    const content = readFileSync(file, "utf8")
    for (const rawLine of content.split(/\r?\n/)) {
      const line = rawLine.trim()
      if (!line || line.startsWith("#") || !line.includes("=")) continue
      const key = line.slice(0, line.indexOf("=")).trim()
      const value = line.slice(line.indexOf("=") + 1).trim().replace(/^["']|["']$/g, "")
      if (ENV_VARS.includes(key) && value) return normalizeEnv(value)
    }
  } catch {
    return null
  }
  return null
}

function branchEnv(branch: string | null): EnvName | null {
  if (!branch) return null
  const b = branch.toLowerCase()
  if (/^(main|master|production|prod)$/.test(b)) return "production"
  if (/(staging|stage|homolog|homologacao|uat|qa)/.test(b)) return "staging"
  if (/^(dev|develop)$/.test(b) || /^(dev\/|dev-|feature\/|fix\/)/.test(b)) return "development"
  return null
}

function detectAmbient(root: string, branch: string | null, mode: string): { env: EnvName; evidence: string } {
  if (mode && mode !== "auto") return { env: mode as EnvName, evidence: `Profile override (environment.mode=${mode})` }

  for (const key of ENV_VARS) {
    const value = process.env[key]
    if (value) return { env: normalizeEnv(value), evidence: `Environment variable ${key}=${value}` }
  }

  let dir = root
  for (let depth = 0; depth < 6; depth++) {
    if (existsSync(join(dir, ".env.production"))) return { env: "production", evidence: "File .env.production present" }
    if (existsSync(join(dir, ".env.staging")) || existsSync(join(dir, ".env.homolog")))
      return { env: "staging", evidence: "File .env.staging / .env.homolog present" }
    const envFile = join(dir, ".env")
    if (existsSync(envFile)) {
      const detected = readEnvFile(envFile)
      if (detected) return { env: detected, evidence: `File ${envFile}` }
    }
    if (existsSync(join(dir, ".git"))) break
    const parent = join(dir, "..")
    if (parent === dir) break
    dir = parent
  }

  const fromBranch = branchEnv(branch)
  if (fromBranch) return { env: fromBranch, evidence: `Git branch '${branch}'` }

  return { env: "development", evidence: "Default workspace fallback (development/local)" }
}

function envFromCommand(command: string): EnvName | null {
  const c = command.toLowerCase()
  if (/--env=(production|prod)|target=prod|\bproduction\b/.test(c)) return "production"
  if (/--env=(staging|stage|homolog)|\bstaging\b|\bhomolog\b/.test(c)) return "staging"
  return null
}

const SEGMENT_SPLIT = /(?:&&|\|\||[;&|\n])/
const EVAL_FORM =
  /(?:^|[\s;&|(])(?:bash|sh|zsh|dash|pwsh|powershell|cmd|iex|invoke-expression)\b[^\n]*?(?:\s-c\b|\s-command\b|\s\/c\b|\s\/k\b)/i
const LEAD_PREFIX = "(?:(?:sudo|env|rtk(?:\\s+proxy)?|time|nohup|command)\\s+)*"

function commandSegments(command: string): string[] {
  return command
    .split(SEGMENT_SPLIT)
    .map((segment) => segment.trim())
    .filter(Boolean)
}

function anchoredTest(pattern: RegExp, text: string): boolean {
  const flags = pattern.flags.includes("i") ? "i" : ""
  const body = pattern.source.replace(/^\\b/, "")
  try {
    return new RegExp("^\\s*" + LEAD_PREFIX + body, flags).test(text)
  } catch {
    return pattern.test(text)
  }
}

function isCatastrophic(pattern: RegExp, command: string): boolean {
  for (const segment of commandSegments(command)) {
    if (anchoredTest(pattern, segment)) return true
  }
  if (/[;&|]/.test(pattern.source) && pattern.test(command)) return true
  if (EVAL_FORM.test(command) && pattern.test(command)) return true
  return false
}

function evaluate(command: string, ambient: EnvName, profile: Profile): Verdict {
  const raw = command.trim()
  if (!raw) return { decision: "allow", reason: "Empty command", env: ambient, useCase: "GENERAL" }

  const cmd = raw.replace(/^\s*rtk(?:\s+proxy)?\s+/i, "")
  const env = envFromCommand(cmd) ?? ambient

  for (const [pattern, reason] of CATASTROPHIC) {
    if (isCatastrophic(pattern, raw)) {
      return {
        decision: profile.safety.catastrophic,
        reason: `[CEH CATASTROPHIC BLOCK] Hard block: ${reason}.`,
        env,
        useCase: "CATASTROPHIC",
      }
    }
  }

  if (env === "development") {
    for (const pattern of SAFE_DEV) {
      if (pattern.test(cmd)) {
        return {
          decision: "allow",
          reason: `Safe development operation permitted (Env: DEVELOPMENT).`,
          env,
          useCase: "FILESYSTEM_SAFE",
        }
      }
    }
  }

  for (const [pattern, desc, useCase] of DESTRUCTIVE) {
    if (pattern.test(cmd) || pattern.test(raw)) {
      const decision = profile.environment.tiers[env]
      const label = env === "production" ? "PRODUCTION LOCK" : env === "staging" ? "HOMOLOGACAO SAFETY GATE" : "DEV PERMITTED"
      const alert =
        decision === "ask"
          ? " ALERTA 1/2 [IMPACTO HML] + ALERTA 2/2 [BACKUP & ROLLBACK MANDATORIOS]."
          : decision === "deny"
            ? " Comando destrutivo terminantemente proibido neste ambiente."
            : " Assegure prontidao de backup e rollback."
      return {
        decision,
        reason: `[CEH ${label}] ${useCase}: ${desc}. Env=${env.toUpperCase()}.${alert}`,
        env,
        useCase,
      }
    }
  }

  return {
    decision: "allow",
    reason: `Command complies with CEH safety policy (Env: ${env.toUpperCase()}).`,
    env,
    useCase: "GENERAL",
  }
}

function detectStack(root: string): string[] {
  const stacks: string[] = []
  const has = (f: string) => existsSync(join(root, f))
  const read = (f: string) => {
    try {
      return readFileSync(join(root, f), "utf8")
    } catch {
      return ""
    }
  }

  if (has("composer.json")) {
    stacks.push("PHP")
    const c = read("composer.json")
    if (c.includes("laravel/framework") || has("artisan")) stacks.push("Laravel")
    if (c.includes("symfony/")) stacks.push("Symfony")
    if (has("phpunit.xml") || has("phpunit.xml.dist")) stacks.push("phpunit")
    if (has("tests/Pest.php") || c.includes("pestphp/pest")) stacks.push("pest")
  }
  if (has("package.json")) {
    stacks.push("Node.js")
    if (has("tsconfig.json")) stacks.push("TypeScript")
    const p = read("package.json")
    if (p.includes('"next"')) stacks.push("Next.js")
    else if (p.includes('"react"')) stacks.push("React")
    if (p.includes('"@nestjs/core"')) stacks.push("NestJS")
    if (p.includes('"vitest"')) stacks.push("vitest")
    if (p.includes('"jest"')) stacks.push("jest")
  }
  if (has("pyproject.toml") || has("requirements.txt")) {
    stacks.push("Python")
    const p = read("pyproject.toml")
    if (p.includes("fastapi")) stacks.push("FastAPI")
    if (p.includes("django")) stacks.push("Django")
    if (p.includes("pytest") || has("conftest.py")) stacks.push("pytest")
  }
  if (has("go.mod")) stacks.push("Go")
  if (has("Cargo.toml")) stacks.push("Rust")
  if (has("Dockerfile")) stacks.push("Docker")
  return stacks
}

type BranchInfo = { branch: string | null; source: string }

function readGitHead(root: string): BranchInfo {
  try {
    const gitMarker = join(root, ".git")
    if (!existsSync(gitMarker)) return { branch: null, source: "no .git marker" }
    let gitDir = gitMarker
    if (statSync(gitMarker).isFile()) {
      const pointer = readFileSync(gitMarker, "utf8").trim()
      const match = pointer.match(/^gitdir:\s*(.+)$/i)
      if (!match) return { branch: null, source: ".git file without gitdir" }
      const target = match[1].trim()
      gitDir = /^(?:[a-zA-Z]:[\\/]|\\\\|\/)/.test(target) ? target : join(root, target)
    }
    const head = readFileSync(join(gitDir, "HEAD"), "utf8").trim()
    const ref = head.match(/^ref:\s*refs\/heads\/(.+)$/)
    if (ref) return { branch: ref[1].trim(), source: "fs .git/HEAD" }
    if (/^[0-9a-f]{40}$/i.test(head)) return { branch: null, source: "detached HEAD" }
    return { branch: null, source: "unparsable HEAD" }
  } catch (error) {
    return { branch: null, source: `fs failed: ${(error as Error).message}` }
  }
}

function readBranchFallback(root: string): BranchInfo {
  try {
    const out = execFileSync("git", ["-C", root, "-c", "safe.directory=*", "branch", "--show-current"], {
      cwd: tmpdir(),
      encoding: "utf8",
    })
    const branch = String(out).trim()
    return { branch: branch || null, source: "execFileSync git -C" }
  } catch (error) {
    return { branch: null, source: `spawn failed: ${(error as Error).message}` }
  }
}

function readBranch(root: string): BranchInfo {
  const head = readGitHead(root)
  if (head.branch) return head
  const spawned = readBranchFallback(root)
  if (spawned.branch) return spawned
  return { branch: null, source: `fs(${head.source}) + spawn(${spawned.source})` }
}

function writeStatus(root: string, payload: Record<string, unknown>): void {
  try {
    writeFileSync(join(root, ".opencode", ".ceh-status.json"), JSON.stringify(payload, null, 2) + "\n", "utf8")
  } catch {}
}

function extractCommand(input: any, stash: Map<string, string>): string {
  if (input.callID && stash.has(input.callID)) return stash.get(input.callID) as string
  if (typeof input.pattern === "string") return input.pattern
  if (Array.isArray(input.pattern)) return input.pattern.join(" ")
  const meta = input.metadata ?? {}
  for (const key of ["command", "cmd", "CommandLine", "args"]) {
    const value = meta[key]
    if (typeof value === "string") return value
  }
  return typeof input.title === "string" ? input.title : ""
}

function statusBlock(profile: Profile, env: EnvName, evidence: string, branch: string | null, stacks: string[]): string {
  const enabled = Object.entries(AGENT_NAMES)
    .filter(([key]) => profile.agents[key] !== false)
    .map(([, name]) => name.replace("ceh-", ""))
    .join(", ")
  return [
    "## CEH PROFILE (resolved)",
    `profile=${profile.profile} risk=${profile.riskDial.default} env=${env.toUpperCase()} evidence=${evidence}`,
    `branch=${branch ?? "n/a"} topology=${profile.environment.topology} stack=${stacks.join(", ") || "undetected"}`,
    `safety tiers: dev=${profile.environment.tiers.development} staging=${profile.environment.tiers.staging} production=${profile.environment.tiers.production} catastrophic=${profile.safety.catastrophic}`,
    `agents: ${enabled}`,
    `token economy: astFirst=${profile.tokenEconomy.astFirst} shellCompression=${profile.tokenEconomy.shellCompression}`,
    "Honor the CLEARER protocol and the Risk Dial; classify facts as OBSERVED/INFERRED/UNKNOWN.",
  ].join("\n")
}

export const CehProfile: Plugin = async ({ directory, worktree }) => {
  const root = directory || worktree
  const profile = readProfile(root)
  const branchInfo = readBranch(root)
  const ambient = detectAmbient(root, branchInfo.branch, profile.environment.mode)
  const stacks = profile.stack.autoDetect ? detectStack(root) : []
  const stash = new Map<string, string>()

  writeStatus(root, {
    generatedAt: new Date().toISOString(),
    root,
    rootReachable: existsSync(root),
    branch: branchInfo.branch,
    branchSource: branchInfo.source,
    env: ambient.env,
    envEvidence: ambient.evidence,
    topology: profile.environment.topology,
    stacks,
    safetyTiers: profile.environment.tiers,
    catastrophic: profile.safety.catastrophic,
    agents: Object.entries(AGENT_NAMES)
      .filter(([key]) => profile.agents[key] !== false)
      .map(([, name]) => name),
  })

  return {
    config: async (cfg) => {
      const tier = profile.environment.tiers[ambient.env]
      const bash: Record<string, Tier> = { "*": "allow" }
      for (const glob of DESTRUCTIVE_GLOBS) bash[glob] = tier
      for (const glob of CATASTROPHIC_GLOBS) bash[glob] = profile.safety.catastrophic

      cfg.permission = { ...((cfg.permission as any) ?? {}), bash }

      cfg.agent = cfg.agent ?? {}
      for (const [key, name] of Object.entries(AGENT_NAMES)) {
        const enabled = profile.agents[key] !== false
        const existing = (cfg.agent as any)[name] ?? {}
        const bashPermission = READ_ONLY_AGENTS.has(name) ? "deny" : bash
        ;(cfg.agent as any)[name] = {
          ...existing,
          disable: !enabled,
          permission: { ...(existing.permission ?? {}), bash: bashPermission },
        }
      }
      if (profile.agents.orchestrator !== false) cfg.default_agent = "ceh-orchestrator"
    },

    "tool.execute.before": async (input, output) => {
      if (input.tool !== "bash") return
      const command = String(output.args?.command ?? output.args?.cmd ?? "")
      if (!command) return
      stash.set(input.callID, command)
      if (!profile.safety.hardBlockBeforeExecution) return
      const verdict = evaluate(command, ambient.env, profile)
      if (verdict.decision === "deny") throw new Error(verdict.reason)
    },

    "permission.ask": async (input, output) => {
      const bashLike = ["bash", "command", "shell"].includes(input.type)
      if (!bashLike && !(input.callID && stash.has(input.callID))) return
      if (!profile.safety.enforcePermissionHook) return
      const command = extractCommand(input, stash)
      if (!command) return
      const verdict = evaluate(command, ambient.env, profile)
      output.status = verdict.decision
    },

    "experimental.chat.system.transform": async (_input, output) => {
      output.system.push(statusBlock(profile, ambient.env, ambient.evidence, branchInfo.branch, stacks))
    },
  }
}

export default CehProfile
