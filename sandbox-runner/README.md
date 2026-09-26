# Sandbox runner

A small standalone service that **runs a suspicious npm package in a throwaway
Docker container and reports what it did**. It is the third tier of the package
verdict (metadata → tarball diff → **sandbox**), for issue #45.

It is separate from the Next.js app because Vercel can't run Docker. Run it on
your own machine or on one Linux VM that has Docker.

## Start it

```bash
# 1. Docker must be running.
# 2. Pick a secret (16+ characters) and put the SAME one in .env.local as INTERNAL_SECRET
INTERNAL_SECRET=<your secret> npm run sandbox-runner
# first start builds the image (about a minute)
```

Tell the app where it is, in `.env.local`:

```
SANDBOX_RUNNER_URL=http://127.0.0.1:8787
```

Leave `SANDBOX_RUNNER_URL` unset and the app simply skips this tier. If it is set
but the runner is down, the verdict records a `sandbox:unreachable` failure (it is
never treated as "clean", and is not cached).

The API only calls the runner for versions the earlier tiers already flagged.

## What happens in one run

Two containers share one scratch volume (a Docker volume, not a folder on your machine):

1. **Install** (network on, *no scripts run*): `npm install --ignore-scripts` downloads the package and its dependencies. No secrets in this container.
2. **Run** (network **off**, fake credentials planted, watched with `strace`): the install scripts run, the package is `require()`d, then it idles 5 seconds.

Fake credentials planted before the package runs: `~/.ssh/id_rsa`, `~/.npmrc`,
`~/.aws/credentials`, `~/.git-credentials`, and the env vars `NPM_TOKEN`,
`GITHUB_TOKEN`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`. Every value contains a
random per-run marker, so a leak can be recognised even if it is base64- or hex-encoded.

Both containers are removed afterwards, along with the volume.

## What it reports (and how the API judges it)

The runner only reports facts; `src/lib/packages/sandbox.ts` decides what they mean.

| Observed | Signal | Effect |
| --- | --- | --- |
| Opened a fake credential file | `sandbox_honeypot_read` (critical) | **block** on its own |
| Fake secret in a command line / network call | `sandbox_token_exfil` (critical) | **block** on its own |
| Tried to reach an unknown host or IP | `sandbox_network` (high) | raises the score |
| Tried to reach github.com / npm | `sandbox_network` (low) | barely counts |
| Started curl, wget, nc, ssh, python, `/dev/tcp`… | `sandbox_process` (high/medium) | raises the score |
| Looked at other sensitive files | `sandbox_sensitive_read` (medium) | raises the score |
| Nothing suspicious | `sandbox_clean` (info) | none |

## How it is locked down

- No `--privileged`, no Docker socket, no host folders mounted.
- Runs as an unprivileged user, **all Linux capabilities dropped**, `no-new-privileges`.
- 512 MB memory, 1 CPU, 256 processes, capped file size, time limits (120 s install, 90 s run).
- The run container has **no network** (only loopback) and a read-only root filesystem.
- The install container is told the host machine's name points to nowhere (`host.docker.internal`).
- The runner listens on `127.0.0.1` only, checks the secret in constant time, validates
  package names/versions before they reach `docker`, refuses to start with a weak secret,
  and accepts at most 2 runs at once.
- The container's environment is built from scratch: nothing from the runner's own environment is passed in.

`npm run sandbox-test` proves the container-side claims from the inside.

## Known limits

- One layer, not a guarantee. Malware can detect a sandbox and behave, and a container
  shares the host kernel: don't run this on a machine you can't afford to lose, and
  prefer a disposable VM for anything beyond the demo.
- **The install step has network access** (it has to download packages) and can reach whatever the
  Docker host can. No package code runs there, but if you deploy this on a VM, block
  that VM's access to internal services at the firewall.
- It is not a full install: no compiler toolchain, so native builds (`node-gyp`) fail
  and are reported as skipped, and scripts that download binaries fail (only recorded as a network attempt).
- Treat "clean" as "nothing suspicious seen", not "safe". A package can wait longer than the
  5-second idle, behave only on certain dates or machines, or notice it is being traced.
- Environment variables can't be seen being read (strace sees system calls, not memory).
  A stolen env token is only noticed when it appears in a command line or network call.

## Files

- `server.mjs`: the HTTP endpoint (`POST /run`, `GET /health`)
- `run.mjs`: the two-container orchestration and the hardening flags
- `analyze-trace.mjs`: turns the strace output into the structured result
- `image/`: what runs inside the container (`plant.mjs`, `driver.mjs`, `entry.sh`)
- `fixtures/`: harmless test packages for `npm run sandbox-test` (only usable when `SANDBOX_ENABLE_FIXTURES=1`)
- `../scripts/verify-sandbox.mts`: offline rule checks · `../scripts/sandbox-test.mts`: real Docker checks

Set `SANDBOX_DEBUG_TRACE=<file>` to dump the raw strace output of a run.
