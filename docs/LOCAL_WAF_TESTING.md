# Local WAF Testing & E2E Validation Guide

This document explains how to run live Web Application Firewalls (WAFs) and Reverse Proxies locally using Docker, audit them with `waf-checker`, and verify automated virtual patch remediation.

---

## 🚀 Quick Start (Automated E2E Suite)

WAF Checker includes a fully automated end-to-end test suite that spins up live Docker containers, runs baseline and patched security audits, verifies virtual patch generation, and cleans up automatically.

```bash
# Run the entire E2E test suite across all platforms
npm run test:e2e

# Or run the script directly with options
bash scripts/e2e-test-wafs.sh

# Test a specific platform
bash scripts/e2e-test-wafs.sh --target caddy
bash scripts/e2e-test-wafs.sh --target haproxy
bash scripts/e2e-test-wafs.sh --target modsec

# Keep containers running after audit for manual exploration
bash scripts/e2e-test-wafs.sh --keep
```

---

## 🏗️ Architecture

```
                  ┌────────────────────────────────────────────────────────┐
                  │                 Docker Network (waf-e2e-net)          │
                  │                                                        │
                  │  ┌───────────────────────┐                             │
                  │  │  waf-test-backend     │ (Port :8081)                │
                  │  │  Unshielded NGINX     │ 0% Block Rate Baseline      │
                  │  └───────────▲───────────┘                             │
                  │              │                                         │
 ┌─────────────┐  │  ┌───────────┴───────────┐                             │
 │             ├──┼─►│ waf-test-modsec       │ (Port :8088) -> 86% Block   │
 │             │  │  │ OWASP ModSecurity CRS │                             │
 │             │  │  └───────────────────────┘                             │
 │             │  │  ┌───────────────────────┐                             │
 │ waf-checker ├──┼─►│ waf-test-caddy        │ (Port :8089) -> 54% Block   │
 │   CLI       │  │  │ Caddy + Virtual Patch │                             │
 │             │  │  └───────────────────────┘                             │
 │             │  │  ┌───────────────────────┐                             │
 │             ├──┼─►│ waf-test-haproxy      │ (Port :8090) -> 54% Block   │
 │             │  │  │ HAProxy + Native ACLs │                             │
 │             │  │  └───────────────────────┘                             │
 │             │  │  ┌───────────────────────┐                             │
 │             ├──┼─►│ waf-test-nginx        │ (Port :8091) -> 54% Block   │
 │             │  │  │ NGINX + Regex Patches │                             │
 └─────────────┘  │  └───────────────────────┘                             │
                  └────────────────────────────────────────────────────────┘
```

---

## 📊 Live Verification Benchmarks

| Platform | Container Image | Port | Baseline Protection | Patched Protection | Key Defense Mechanism |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **Unshielded Backend** | `nginx:alpine` | `:8081` | **0%** (0/50) | — | Raw upstream target without WAF |
| **OWASP ModSecurity CRS** | `owasp/modsecurity-crs:nginx` | `:8088` | **86%** (43/50) | **94%** (47/50) | Paranoia Level 1 + CRS Anomaly Scoring + `SecRule` |
| **OWASP Coraza WAF** | Pure Go / `corazawaf/v3` | `:8093` | **86%** (43/50) | **94%** (47/50) | Next-Gen Go engine + Embedded CRS + Hotfix `patch.conf` |
| **Caddy Server** | `caddy:alpine` | `:8089` | **0%** | **54%** (27/50) | Named Matchers (`@waf_patch_*`) + CEL Query Regex |
| **HAProxy** | `haproxy:alpine` | `:8090` | **0%** | **54%** (27/50) | Native ACLs (`path_end`, `query -m sub`, `query -m reg`) |
| **NGINX Reverse Proxy** | `nginx:alpine` | `:8091` | **0%** | **54%** (27/50) | Native `location ~*` + `$query_string` PCRE2 regex |

---

## 🛠️ Manual Testing Step-by-Step

If you want to manually start and experiment with individual containers:

### 1. Start the Docker Stack
```bash
docker compose -f docker/docker-compose.e2e.yml up -d
```

### 2. Audit the Unshielded Baseline
```bash
waf-checker check http://127.0.0.1:8081/ --allow-local
# Expected: 0% Blocked, 50 Bypasses detected
```

### 3. Audit OWASP ModSecurity CRS
```bash
waf-checker check http://127.0.0.1:8088/ --allow-local
# Expected: 86% Blocked (43/50)
```

Run reverse engineering against ModSecurity:
```bash
waf-checker check http://127.0.0.1:8088/ --allow-local --reverse
# Displays:
# - Active CRS Rule IDs (920xxx, 930xxx, 932xxx, 941xxx, 942xxx)
# - Anomaly Scoring Mode & Threshold
# - Body Limit Window
```

### 4. Audit Caddy Server with Virtual Patches
```bash
waf-checker check http://127.0.0.1:8089/ --allow-local
# Expected: 54% Blocked (27/50)
```

### 5. Audit HAProxy with Native ACLs
```bash
waf-checker check http://127.0.0.1:8090/ --allow-local
# Expected: 54% Blocked (27/50)
```

### 6. Audit NGINX Reverse Proxy
```bash
waf-checker check http://127.0.0.1:8091/ --allow-local
# Expected: 54% Blocked (27/50)
```

### 7. Generate Real-Time Remediation Patches
Generate virtual patches for any remaining bypasses on the fly:
```bash
# Generate Caddy patches
waf-checker check http://127.0.0.1:8089/ --allow-local --patch caddy --patch-output ./my-caddy-patch.caddyfile

# Generate HAProxy patches
waf-checker check http://127.0.0.1:8090/ --allow-local --patch haproxy --patch-output ./my-haproxy-patch.cfg

# Generate ModSecurity / Coraza patches
waf-checker check http://127.0.0.1:8088/ --allow-local --patch modsecurity --patch-output ./my-modsec-patch.conf

# Generate Terraform AWS WAF rule group
waf-checker check http://127.0.0.1:8081/ --allow-local --patch aws --patch-output ./waf_rules.tf
```

### 8. Cleanup Containers
```bash
docker compose -f docker/docker-compose.e2e.yml down -v
```

---

## ✅ Validating Cloud WAF Rules Offline (AWS / Azure)

Cloud WAFs (AWS WAFv2, Azure Front Door) have no local engine, so generated rules
cannot be behaviourally tested without deploying to the cloud. Two layers of
offline checks guard rule *formation* instead:

### Structural invariants (always in CI)

`packages/core/test/virtual-patch-invariants.spec.ts` runs every generated rule
through invariant checks across all inspection locations (query / body / header /
uri) with no external dependencies. It enforces, among others:

- **AWS** – a `ByteMatchStatement` that applies a `LOWERCASE` transform must use a
  lowercase `SearchString` (otherwise AWS lowercases only the field and the rule
  never matches); every `Body` field declares the required `OversizeHandling`;
  bundle rule priorities are unique.
- **Azure** – the ARM match-condition field is `negateCondition` (never the
  documented typo `negationConditon`, see [Azure/azure-cli#31807](https://github.com/Azure/azure-cli/issues/31807)).

```bash
cd packages/core && npm test
```

### Official AWS validator (cfn-lint)

The generated AWS rules can also be checked with AWS's own `cfn-lint`, fully
offline and without credentials. `scripts/validate-aws-cfn.mjs` wraps them in an
`AWS::WAFv2::RuleGroup` template (adjusting the one API→CloudFormation casing
difference, `ARN`→`Arn`) and lints it:

```bash
# Install cfn-lint into an isolated venv (avoids clobbering system PyYAML)
python3 -m venv .cfnenv && ./.cfnenv/bin/pip install cfn-lint

# Validate (falls back to printing the template path if cfn-lint is absent)
PATH="$PWD/.cfnenv/bin:$PATH" npm run validate:aws:cfn
```

> The native rules target the `aws wafv2` CLI/API, where the regex-pattern-set
> reference field is `ARN`. CloudFormation spells the same field `Arn`; the
> script applies only that rename, so a clean `cfn-lint` run confirms the rule
> structure itself is valid.

---

## 🛡️ OWASP Coraza Standalone Testing

Coraza can be run as a lightweight Go reverse-proxy without Docker:

```bash
cd docker/coraza
go build -o coraza-proxy main.go
./coraza-proxy

# In another terminal:
waf-checker check http://127.0.0.1:8093/ --allow-local
# Expected: 86% blocked baseline, 94% with patch.conf
```
