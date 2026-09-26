# specter-guard-mcp

Checks npm packages against Specter **before** a coding agent installs them. It works with Claude Code, Codex CLI, Cursor, Gemini CLI, Windsurf and Claude Desktop, and has two layers:

| Layer | What it does | Blocks? |
| --- | --- | --- |
| MCP server | Tools the agent calls before adding a dependency: `check_package`, `check_packages`, `check_install_command`, `check_lockfile` | No, it advises |
| Claude Code hook | Runs before every Bash command; denies a `block` install, asks the user on `warn` | Yes |
| PATH shims | `npm` / `npx` / `pnpm` / `yarn` / `bun` / `bunx` wrappers that check an install before running it, for any agent or human | Yes |

Design: [`../IMPLEMENTATION.md`](../IMPLEMENTATION.md).

## Install

Not on npm yet, so run it from this checkout. (The npm name `specter-mcp` belongs to an unrelated package; this one is `specter-guard-mcp`.)

```bash
cd mcp
npm ci
node specter-mcp.mjs print-config          # every snippet below, with this machine's absolute paths
```

The server calls Specter's check API. Point it at a deployment that has `/api/v1/check`:

```bash
export SPECTER_API_URL=https://specter-seven.vercel.app   # the default
export SPECTER_API_URL=http://localhost:3000              # a local `npm run dev`
```

If the URL doesn't answer as the check API, every result is `warn` ("did not answer as the Specter check API"), never `allow`.

## Claude Code

```bash
node specter-mcp.mjs print-config claude
```

This prints two things:
1. a `claude mcp add ...` command for the MCP server;
2. a `PreToolUse` hook to merge into `~/.claude/settings.json` (all projects) or `.claude/settings.json` (this project):

```json
{ "hooks": { "PreToolUse": [ { "matcher": "Bash", "hooks": [
  { "type": "command", "command": "\"/path/to/node\" \"/path/to/mcp/specter-mcp.mjs\" hook claude", "timeout": 90 } ] } ] } }
```

| Check result | Hook decision |
| --- | --- |
| `block` | `deny`: the command never runs |
| `warn` | `ask`: you decide, not the agent |
| `allow` | no output; normal permissions apply |
| API unreachable, rate limited, unfinished | `ask` with "could not verify" |

Add `--deep` after `hook claude` to resolve the full dependency tree of an `npm install` (in a temporary copy of the project) and check every transitive package. It's slower and uses the lockfile quota (10 per hour).

## Codex CLI, Cursor, Gemini CLI, Windsurf, Claude Desktop

```bash
node specter-mcp.mjs print-config codex     # ~/.codex/config.toml
node specter-mcp.mjs print-config cursor    # .cursor/mcp.json (same shape for Windsurf, Claude Desktop)
node specter-mcp.mjs print-config gemini    # ~/.gemini/settings.json
```

These agents get the MCP tools and the server's instructions ("call a check before installing; never install a `block`"). For Codex, also add to `AGENTS.md`:

> Run `check_install_command` before any package install; never install a package whose verdict is `block`.

For a hard block in these agents, install the shims.

## PATH shims (any agent, any human)

```bash
node specter-mcp.mjs shim install           # writes ~/.specter/bin/{npm,npx,pnpm,yarn,bun,bunx}(.cmd)
export PATH="$HOME/.specter/bin:$PATH"      # must come FIRST; add to your shell profile
```

- Non-install commands (`npm run`, `npm test`, ...) go straight to the real binary.
- `npm install` / `npm ci` go through [`../cli/specter-guard.mjs`](../cli/specter-guard.mjs) when it's present (full-tree check), or `SPECTER_GUARD_CLI=/path/to/specter-guard.mjs`.
- Everything else (`npx`, `pnpm add`, `yarn add`, `bun add`, ...) is checked package by package.
- `block` stops the install (exit 1). A check that fails stops it (exit 2, fail closed). `warn` is printed and the install continues.
- `SPECTER_GUARD=warn-only` reports without stopping. `SPECTER_GUARD=off` disables the check. Set these yourself, never let the agent do it.
- `node specter-mcp.mjs shim uninstall` removes them.

## Tools

| Tool | Input | Notes |
| --- | --- | --- |
| `check_package` | `name`, `version?` (exact, range or tag; default `latest`), `minReleaseAgeHours?`, `strict?` | Ranges and tags are resolved the way npm does; the result names the exact version checked |
| `check_packages` | `packages: [{name, version?}]` (max 50) | Overall verdict is the worst one |
| `check_install_command` | `command`, `cwd?` | npm/npx/pnpm/yarn/bun, including `cd x && ...`, `npm exec`, `pnpm dlx`, aliases. Git, URL, path and `workspace:` sources come back as `warn` ("cannot verify") |
| `check_lockfile` | `path?` (default `./package-lock.json`) | Returns counts and only the flagged packages |

Every result has `verdict`, `package`, `requested`, `score`, `reasons[]`, `action`, `checkedAt` and `source`, as both `structuredContent` and text. A `block` is a normal result, not an MCP error; only bad input (an invalid name, a missing lockfile) is `isError`.

Reasons text comes from package metadata and advisories, which an attacker can write. It is stripped of control and bidi characters, capped at 200 characters, and only ever returned as data.

## Environment

| Variable | Effect |
| --- | --- |
| `SPECTER_API_URL` | Check API base URL (default `https://specter-seven.vercel.app`) |
| `SPECTER_NPM_REGISTRY` | Registry used to resolve ranges and tags (default `https://registry.npmjs.org`) |
| `SPECTER_MIN_RELEASE_AGE_HOURS` | Default cooldown for every check |
| `SPECTER_STRICT=1` | A cooldown hit is `block` instead of `warn` |
| `SPECTER_ALLOW=a@1.0.0,b@2.0.0` | Versions exempt from the **cooldown** (the API's `allow[]`; it doesn't override a `block`) |
| `SPECTER_GUARD=off\|warn-only` | Shims only |
| `SPECTER_SHIM_DIR` | Shim directory, if not `~/.specter/bin` |

## Limits

- **MCP is advisory.** Only the hook and the shims actually stop an install.
- **The API rate limits per IP:** 120 single checks and 10 lockfile checks per hour. Over the limit, results are `warn` / `ask`, never `allow`.
- **npm only.** A bare `pnpm install` / `yarn` / `bun install` installs from a lockfile Specter can't read yet, so it's reported as unverifiable.
- **The shell parser is not a full shell.** Installs hidden inside `eval`, `$(...)` or scripts aren't seen by the hook. The shims catch those, because they sit on `PATH`.
- **Detection quality is the engine's.** See §10 of `IMPLEMENTATION.md`.

## Tests

```bash
npm test     # parser, API client, MCP over stdio, hook and shims, against a local stub API
```
