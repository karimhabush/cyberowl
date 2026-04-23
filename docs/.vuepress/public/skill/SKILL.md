---
name: cyberowlai
description: >
  Check if recent cybersecurity alerts from 10 international CERTs affect
  your current project. Use when the user asks about security vulnerabilities,
  CVEs, "is my project affected", "any new security alerts", "check for
  vulnerabilities", "cyberowlai", or "/cyberowlai". Also trigger when the user is
  working on dependency updates, Dockerfile changes, security audits, or any
  security-related task — even if they don't explicitly mention CyberOwl AI.
  Trigger on questions like "should I update my dependencies", "are there any
  new CVEs for X", "security check", or "what vulnerabilities should I worry
  about". If the user mentions a specific CVE or advisory ID, use this skill
  to cross-reference it against their stack.
---

# CyberOwl Security Check

Cross-reference recent cybersecurity alerts from 10 international CERTs
against the user's project to surface vulnerabilities that actually matter to
them.

## High-level workflow

1. **Discover the project's full tech stack** (dependencies, infra, frameworks)
2. **Fetch the alert feed** from `https://cyberowlai.com/alerts.json`
3. **Match alerts against the stack** using tiered confidence
4. **Report** only what's relevant, plus always-flag critical alerts

Run steps 1 and 2 in parallel when possible — don't make the user wait.

---

## Step 1 — Deep project discovery

Build a comprehensive inventory. Go beyond top-level deps — look at
transitive dependencies, container base images, CI tool versions, and code
import patterns.

### 1a. Find all dependency and config files

Use Glob to locate files. Search for all of the following (skip categories
that return nothing):

| Category | Files to find |
|---|---|
| **Node.js** | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| **Python** | `requirements.txt`, `Pipfile`, `Pipfile.lock`, `pyproject.toml`, `poetry.lock`, `setup.py`, `setup.cfg` |
| **Go** | `go.mod`, `go.sum` |
| **Ruby** | `Gemfile`, `Gemfile.lock` |
| **Java/Kotlin** | `pom.xml`, `build.gradle`, `build.gradle.kts` |
| **Rust** | `Cargo.toml`, `Cargo.lock` |
| **PHP** | `composer.json`, `composer.lock` |
| **C#/.NET** | `*.csproj`, `packages.config`, `Directory.Packages.props` |
| **Swift** | `Package.swift` |
| **Dart/Flutter** | `pubspec.yaml` |
| **Elixir** | `mix.exs` |
| **Perl** | `cpanfile` |
| **Containers** | `Dockerfile`, `Containerfile`, `docker-compose.yml`, `docker-compose.yaml` |
| **Kubernetes** | `*.yaml` in `k8s/`, `kubernetes/`, `deploy/`, `manifests/` |
| **Helm** | `Chart.yaml`, `values.yaml` |
| **Terraform** | `*.tf` |
| **Ansible** | `*.yml` in `ansible/`, `playbooks/` |
| **Vagrant** | `Vagrantfile` |
| **CI/CD** | `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`, `.circleci/config.yml`, `azure-pipelines.yml` |
| **Build** | `Makefile`, `Taskfile.yml`, `Justfile` |
| **Web servers** | `nginx.conf`, `nginx/*.conf`, `apache2.conf`, `.htaccess`, `httpd.conf`, `Caddyfile`, `traefik.yml`, `traefik.toml` |
| **Databases** | `prisma/schema.prisma`, `config/database.yml`, `alembic.ini` |
| **Env files** | `.env.example`, `.env.sample` |
| **Version files** | `.node-version`, `.nvmrc`, `.python-version`, `.ruby-version`, `.go-version`, `.java-version`, `.tool-versions`, `runtime.txt` |
| **Security** | `.snyk`, `snyk.json`, `.trivyignore`, `security.txt`, `renovate.json`, `dependabot.yml` |

### 1b. Read discovered files and extract

From each file, extract:

- **Package names and versions** (direct + transitive where lock files exist)
- **Base images** from Dockerfiles (`FROM` lines) — note the OS, runtime, and version
- **System packages** installed via `apt-get install`, `apk add`, `yum install`
- **Action versions** from CI workflows (e.g. `actions/checkout@v4`)
- **Cloud providers** from Terraform (`provider "aws"`, resource prefixes)
- **Database types** from ORMs, connection strings, Docker services
- **Service names** from env variable patterns (`REDIS_URL`, `POSTGRES_HOST`, `MONGO_URI`, `KAFKA_BROKER`)

### 1c. Grep for framework and library patterns in code

Use Grep to detect frameworks and libraries that might not appear in
dependency files. Search source directories for these import patterns:

- **Frameworks:** `import express`, `from django`, `import spring`, `using Microsoft.AspNetCore`, `import React`, `import Vue`, `from angular`
- **Auth:** `passport`, `jsonwebtoken`, `jwt`, `oauth`, `auth0`, `firebase-auth`, `keycloak`
- **Crypto:** `bcrypt`, `argon2`, `crypto`, `openssl`, `sodium`
- **HTTP clients:** `axios`, `fetch`, `requests`, `httpx`, `okhttp`, `urllib3`
- **Message queues:** `rabbitmq`, `kafka`, `celery`, `bull`, `sidekiq`, `nats`
- **Cloud SDKs:** `aws-sdk`, `@google-cloud`, `azure`, `boto3`

### 1d. Compile the stack inventory

Organize everything you found into a structured inventory:

- **Languages** (with versions where known)
- **Frameworks** (with versions)
- **Direct dependencies** (key ones — no need to list every tiny utility)
- **Databases & data stores**
- **Infrastructure** (container images, cloud providers, orchestration)
- **CI/CD** (platform and notable tool versions)
- **Web servers & proxies**
- **Security tools** already in use

This inventory drives the matching in Step 3 and is shown to the user in the
final output so they can verify completeness.

---

## Step 2 — Fetch the alert feed

Use WebFetch to retrieve `https://cyberowlai.com/alerts.json`.

The JSON structure:

```
{
  "generated_at": "2026-04-23T10:00:54Z",
  "sources": {
    "<SOURCE_NAME>": {
      "items": [
        {
          "title": "...",
          "link": "https://...",
          "description": "...",
          "date": "Apr 20, 2026"
        }
      ]
    }
  }
}
```

Sources: US-CERT, CERT-FR, MA-CERT, IBM-X-FORCE-EXCHANGE, ZERODAYINITIATIVE,
OBS-Vigilance, VulDB, HK-CERT, CA-CCS, EU-CERT (~90 alerts total).

**If the fetch fails:** Tell the user the feed is unavailable, suggest they
check https://cyberowlai.com/activity/ directly, and still show the detected
stack inventory so the visit isn't wasted.

---

## Step 3 — Intelligent matching

Cross-reference every alert's **title** and **description** against the full
stack inventory. Classify matches into tiers:

### HIGH — Direct dependency or component match

The alert explicitly names a package, library, or tool the project uses.

Examples:
- Alert says "jQuery 3.6 vulnerability" → project has jQuery → **MATCH**
- Alert says "OpenSSL" → Dockerfile installs openssl → **MATCH**
- Alert says "nginx" → docker-compose has nginx service → **MATCH**
- Alert says "PostgreSQL" → project uses PostgreSQL → **MATCH**

### MEDIUM — Framework or platform match

The alert targets a broader platform that encompasses something in the stack.

Examples:
- Alert says "Spring Framework" → project uses Spring Boot → **MATCH**
- Alert says "Linux kernel" → Dockerfile uses a Linux base image → **MATCH**
- Alert says "Chrome/Chromium" → project uses Puppeteer or Playwright → **MATCH**
- Alert says "Node.js" → project is a Node app → **MATCH**

### LOW — Category match

The alert is about a *class* of technology the project uses, even without a
direct name match.

Examples:
- Alert about "DNS vulnerability" → project uses a DNS library → **FLAG**
- Alert about "TLS/SSL" → project uses HTTPS → **FLAG**
- Alert about "container escape" → project uses Docker → **FLAG**

### CRITICAL — Always flag regardless of stack

Some alerts are important enough to surface no matter what the project uses.
Flag any alert where:

- Title contains: "actively exploited", "zero-day", "0-day", "critical RCE",
  "remote code execution", "supply chain", "pre-auth", "unauthenticated"
- A CVE with CVSS ≥ 9.0 is mentioned
- The alert comes from CISA's Known Exploited Vulnerabilities catalog
  (look for "Known Exploited Vulnerabilities" in title or description)

---

## Step 4 — Output format

Use this structure for the report. Keep it concise — only show alerts that
matched or are critical. Don't dump the full 90-alert feed.

```
## CyberOwl Security Check
Last updated: [generated_at timestamp] | [N] sources checked | [total] alerts scanned

### Alerts matching your project ([count] found)

**HIGH — Direct dependency match:**
| Alert | Source | Matched Component | Date |
|---|---|---|---|
| [Title](link) | SOURCE | component-name (where detected) | date |

**MEDIUM — Platform/framework match:**
| Alert | Source | Related To | Date |
|---|---|---|---|
| [Title](link) | SOURCE | platform (context) | date |

**LOW — Category match:**
| Alert | Source | Related To | Date |
|---|---|---|---|
| [Title](link) | SOURCE | category (context) | date |

### Critical alerts (always worth knowing)
| Alert | Source | Why Flagged | Date |
|---|---|---|---|
| [Title](link) | SOURCE | Actively exploited / Zero-day / etc. | date |

### Your detected stack
- **Languages:** ...
- **Frameworks:** ...
- **Databases:** ...
- **Infrastructure:** ...
- **CI/CD:** ...
```

**When no direct matches are found:** Skip the matching tables and show only
the "Critical alerts" section with a note: "No alerts directly matched your
detected stack, but these critical advisories are worth reviewing." Always
include the detected stack section so the user can verify nothing was missed.

**Omit empty tiers.** If there are no HIGH matches, don't show that table.
Same for MEDIUM and LOW.

---

## Important notes

- **Be specific about where you found each component.** Don't just say
  "nginx" — say "nginx (from docker-compose.yml service)" or "OpenSSL (apt-get
  install in Dockerfile)". This helps the user triage.
- **Don't over-match.** A generic alert about "multiple vulnerabilities in
  various products" with no specific technology named should not match
  anything. Matching must be based on actual technology names in the alert.
- **Conciseness matters.** The user wants a quick answer: "Am I affected?"
  Don't pad the output. If there are 0 matches and 2 critical alerts, the
  report should be short.
- **Show your work on the stack** so the user can catch anything you missed
  and re-run if needed.