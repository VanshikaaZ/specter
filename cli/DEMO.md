# specter-guard demo

Packages that npm **still serves today** but that Specter **blocks**. Each is listed as
malicious code in the GitHub/OSV advisory database. Last checked: 2026-09-26.

> **Never install these with plain `npm install`.** They are real malware and their
> install scripts would run. Only run them through `specter-guard` (which stops before
> installing), and do the demo in an empty scratch folder.

## Live malicious packages (all return `block`)

| Package@version | Why it is blocked |
| --- | --- |
| `eslint-config-compact-base@1.0.0` | malicious (MAL-2026-17157), brand-new package |
| `@digift/cli@99.99.100` | malicious, dependency-confusion style version number |
| `@airbnb-extended/typescript-config@99.9.1` | malicious, dependency-confusion style version number |
| `building-build@1.0.0` | malicious, brand-new package |
| `turbo-ws@1.0.0` | malicious, brand-new package |
| `moidevl@1.0.0` | malicious, brand-new package |
| `pino-testkit@10.4.5` | malicious, brand-new package |
| `cache-swipper@3.6.0` | malicious, brand-new package |
| `analytics-widget@1.0.0` | malicious, brand-new package |
| `hachutis@1.0.6` | malicious, brand-new package |

npm can remove any of them at any time. Before the demo, check that each one you plan
to use is still served (prints the version if live, an error if removed):

```powershell
npm view eslint-config-compact-base@1.0.0 version
```

## Setup (once)

Until the app is deployed, point the CLI at your local API.

```powershell
# terminal 1, in the specter repo
npm run dev

# terminal 2 (a NEW terminal, so the variable is picked up)
setx SPECTER_API_URL http://localhost:3000     # once; or pass --api-url each time
cd cli; npm link; cd ..                        # once; installs the `specter-guard` command
```

## The demo

Use an empty folder with a `package.json`:

```powershell
mkdir demo-project; cd demo-project
npm init -y
```

**1. A malicious package is stopped**

```powershell
specter-guard install eslint-config-compact-base@1.0.0
```

Expected: `BLOCK ... [critical] Reported as malicious code`, then
`Install stopped`. Exit code 1. No `node_modules`, and `package.json` is unchanged.

```powershell
$LASTEXITCODE     # 1
dir               # only package.json
```

**2. A safe package installs normally**

```powershell
specter-guard install is-odd@3.0.1
```

Expected: `checked, nothing to flag`, then the normal npm install, exit code 0.

**3. Escape hatches**

```powershell
specter-guard install turbo-ws@1.0.0 --json                            # machine-readable, exit 1
specter-guard install turbo-ws@1.0.0 --allow turbo-ws@1.0.0            # accept it on purpose
specter-guard install turbo-ws@1.0.0 --warn-only                      # report but install anyway
```

Do **not** run the last two with the packages above on a machine you care about: they
install real malware. They exist to show the flags, so use them only in a throwaway VM
or skip them in the demo.

**4. Whole lockfile (`npm ci`)**

`cli/demo/` holds a project whose lockfile contains `event-stream@3.3.6`, the 2018
attack. npm has since removed that version, but a lockfile that names it is still
checked, and blocked:

```powershell
cd ..\cli\demo
specter-guard ci
```

Expected: `BLOCK event-stream@3.3.6 ... Reported as malicious code (GHSA-mh6f-8j2x-4483)`,
exit code 1. This one is safe to run: `npm ci` is never reached.

## Talking points

- Plain `npm install` serves all ten of these right now, and would run their install
  scripts. `npm audit` only reports afterwards.
- Specter resolves the tree with `--ignore-scripts`, checks it, and only then installs.
- It is one layer, not a guarantee: it only protects people who run it, and a package
  no one has reported yet is caught only by the diff and sandbox tiers.
