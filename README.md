# LogHawk — live demo

The public deployment of [**LogHawk**](https://github.com/Cyb3r-Abdullah/loghawk),
a blue-team log detection engine.

**Live:** https://loghawk-demo.vercel.app

This repository holds **no detection code**. It is deployment configuration
only — the engine installs from the main repository at build time, so there is
one source of truth for the rules and this repo can never drift out of sync.

## What the demo runs

On first request each serverless instance parses the bundled synthetic logs —
Linux `auth.log`, an nginx access log and Windows Security events, 180 events
across the three — and runs all ten ATT&CK-mapped detection rules over them.
It reconstructs a full intrusion: recon sweep, SQL injection, account
enumeration, a 40-attempt brute force, the login that succeeds, `sudo` reading
`/etc/shadow`, and a new account added to Domain Admins.

## Differences from running it locally

Serverless changes three things, and each is handled deliberately in
[`api/index.py`](api/index.py):

**The filesystem is read-only apart from `/tmp`.** The alert database lives
there and is seeded on the first request an instance serves. Triage changes
really are written to SQLite — they just vanish when the instance recycles.
The dashboard says so rather than pretending otherwise.

**The API is public, so two endpoints were removed.** The main repository's
[SECURITY.md](https://github.com/Cyb3r-Abdullah/loghawk/blob/main/SECURITY.md)
states that `/api/scan` reads server-side paths supplied by the caller and must
not be exposed. This deployment deletes that route and the file-upload route,
replacing them with a fixed-scope rescan that can only ever read the synthetic
samples shipped alongside it. Everything else — the engine, the rules, the
dashboard — is untouched.

**Cold starts.** The first request after an idle period takes a second or two
while the instance boots and seeds. Subsequent requests are immediate.

## Endpoints

| Method | Path | |
|---|---|---|
| `GET` | `/` | SOC dashboard |
| `GET` | `/docs` | Interactive OpenAPI reference |
| `GET` | `/api/health` | Service status and rule count |
| `GET` | `/api/rules` | Detection catalog with ATT&CK mappings |
| `GET` | `/api/alerts` | Filter by severity, rule, source IP, triage status |
| `GET` | `/api/stats` | Counts by severity, status and rule |
| `PATCH` | `/api/alerts/{id}` | Update triage status (ephemeral) |
| `POST` | `/api/scan` | Rescan the bundled samples — takes no input |
| `GET` | `/api/export/{csv,markdown}` | Export the queue or an incident report |

## Deploying your own

```bash
git clone https://github.com/Cyb3r-Abdullah/loghawk-demo.git
cd loghawk-demo
vercel            # preview
vercel --prod     # production
```

No environment variables are required. The demo makes no outbound network
calls and needs no API keys — geolocation reads a bundled offline table.

## Source

Engine, detection rules, tests and documentation:
**[github.com/Cyb3r-Abdullah/loghawk](https://github.com/Cyb3r-Abdullah/loghawk)**
