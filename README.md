# 🛡️ SentinelGuard — Intelligent Web Application Firewall (WAF) & Threat Intelligence Platform

[![Java 21/25](https://img.shields.io/badge/Java-21%20%7C%2025%20(Loom)-orange.svg)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.3.4-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![CI/CD](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions%20%E2%86%92%20OCI-blue.svg)](.github/workflows/deploy.yml)
[![Security](https://img.shields.io/badge/WAF-OWASP%20Top%2010-red.svg)](https://owasp.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)

> **High-Signal Enterprise Security & Distributed Systems Project**: Built with Java 21 (Project Loom Virtual Threads), Spring Boot 3.3, and Reactive Network Intelligence. Intercepts, scores, and neutralizes web vulnerabilities in real time before authentication, while providing automated 6-month retention lifecycles, pluggable multi-database persistence (H2 / PostgreSQL / MySQL), and automated CI/CD deployments to Oracle Cloud Infrastructure (OCI).

---

## 🚀 Key Architectural Capabilities

### 1. ⚡ High-Throughput WAF Pre-Auth Inspection Engine (Java 21 Loom)
- **Zero-Blocking Concurrency**: Leverages Java 21 Virtual Threads (`spring.threads.virtual.enabled=true`) for sub-millisecond AST pattern tokenization across URI paths, query strings, headers, and request payloads.
- **Deep Exploit Coverage**:
  - **SQL Injection (SQLi)**: Tautologies (`' OR 1=1--`), UNION SELECT exfiltration, stacked queries (`DROP TABLE`), blind sleep/benchmark injections.
  - **Cross-Site Scripting (XSS)**: Script tags, inline event attributes (`onload`, `onerror`), SVG payloads, JavaScript protocol URIs, cookie theft vectors.
  - **Remote Code Execution (RCE)**: Shell command chaining (`| cat /etc/passwd`), `$()` command substitutions, reverse shells, Log4j JNDI injection (`${jndi:ldap://...}`).
  - **Path Traversal & LFI**: Directory climbing (`../`, `..\\`), double-encoded payloads (`%2e%2e%2f`), and attempts to read sensitive system files.
  - **SSRF & Cloud Metadata**: Intercepts AWS/GCP/OCI metadata exfiltration (`http://169.254.169.254/latest/meta-data/`).
  - **XXE & Deserialization**: External entity declarations, polymorphic JSON auto-type gadgets, and Java serialized payloads.
  - **SSTI & NoSQL Injection**: Jinja2/Freemarker expression injections (`{{7*7}}`) and MongoDB query operators (`$ne`, `$regex`).

### 2. 🗄️ Pluggable Multi-Database Persistence & 6-Month Data Retention Lifecycle
- **Zero-Setup File Database**: Uses persistent disk-backed H2 (`./data/sentineldb`) by default—zero external setup required for local development and demoing.
- **Production RDBMS Profiles**: One-flag activation for PostgreSQL (`--spring.profiles.active=postgres`) or MySQL (`--spring.profiles.active=mysql`).
- **Automated Retention Daemon**: `DataRetentionService` runs daily at 02:00 AM (`@Scheduled(cron = "0 0 2 * * *")`) to automatically purge historical incidents older than 180 days (`sentinel.waf.data-retention.days=180`) while generating immutable audit trail records.

### 3. 🚀 Automated CI/CD Pipeline (GitHub Actions ➔ OCI VM)
- **Continuous Integration**: Triggers on `push` and `pull_request` to compile, run unit & exploit test suites with Java 21, and package production JAR artifacts.
- **Continuous Deployment**: Securely connects via SSH to Oracle Cloud VM (`140.245.250.50`), fetches latest commits, executes zero-downtime container rollouts with `docker compose up -d --build`, and probes endpoint health automatically.

### 4. 🌐 DNS & Domain Threat Intelligence (Multi-Domain)
- **Deep DNS Resolution (`dnsjava`)**: Resolves `A`, `AAAA`, `MX`, `TXT`, `NS`, and `CNAME` records with latency benchmarks.
- **Raw WHOIS Extraction (`commons-net`)**: Connects to TLD registrar servers to parse domain registration age, registrar entity, and expiration timelines.
- **SSL/TLS X.509 Inspector**: Probes port 443 with SNI host headers to validate certificate chains, remaining validity days, and cipher suite strength.

### 5. 👑 Role-Based Access Control (RBAC) & Red-Team Attack Sandbox
- **Super Administrator (`ROLE_SUPER_ADMIN`)**: Unlocked access to the **Red-Team Attack Simulation Sandbox** to fire controlled penetration tests (SQLi, XSS, RCE, 50-Request Virtual-Thread DoS Floods) and verify real-time neutralization.
- **Security Analyst (`ROLE_SECURITY_ANALYST`)**: Manages domain inventory, inspects live threat radar feeds, and manually triggers IP firewall bans/releases.
- **Auditor (`ROLE_AUDITOR`)**: Read-only compliance portal with immutable audit logging.

---

## 👥 Demo RBAC Credentials

| Persona | Username | Password | Assigned Role | Capabilities |
| :--- | :--- | :--- | :--- | :--- |
| **Krishna Singamsetti** | `krishna` | `krishna` | `ROLE_SUPER_ADMIN` | Full Access + **Red-Team Attack Simulation Sandbox** |
| **Alex Mercer** | `alex` | `alex` | `ROLE_SECURITY_ANALYST` | Domains, Live Incident Feeds, Firewall Jails |
| **Sarah Connor** | `sarah` | `sarah` | `ROLE_AUDITOR` | Read-only Reports, Live Radar & Audit Logs |

---

## 💻 Quick Start Guide (Local Development)

### 1. Run with Maven
```bash
cd E:\PracticeProjects\sentinel-guard
.\mvnw.cmd spring-boot:run
```

### 2. Access the Dashboard
Open your browser and navigate to:
👉 **[http://localhost:8090](http://localhost:8090)**

---

## 🐳 Running with Docker & PostgreSQL

```bash
cd E:\PracticeProjects\sentinel-guard
docker compose up --build -d
```

Check running containers:
```bash
docker compose ps
docker compose logs -f sentinel-guard
```

---

## ☁️ OCI Cloud Deployment & CI/CD Setup

See the complete step-by-step CI/CD and deployment guide:
👉 **`OCI_DEPLOYMENT_GUIDE.md`**

---

## 🧪 Testing External Traffic & Live Inspection

DNS can live **anywhere** (Hostinger, Cloudflare, Route53, GoDaddy). SentinelGuard does not talk to the registrar. The only requirement is an **A record** (and optionally AAAA) pointing at SentinelGuard's public IP (`140.245.250.50`). Nginx catch-all forwards that Host into the WAF; the first request auto-adds the domain to inventory and Threat Radar.

Set **Origin URL** in the dashboard to the real app backend (the old Hostinger/VPS site). Without origin, attacks are still blocked and radared; clean traffic returns 502 `NO_ORIGIN`.

With `usertesting.singamsettikrishna.in` A-record pointing at SentinelGuard, **all origin APIs** are inspected then proxied to that domain's `originUrl` (default `http://127.0.0.1:8085`).

```bash
# Live Host interception (JSON body) — blocked + Threat Radar
curl -i -H "Host: usertesting.singamsettikrishna.in" \
  -H "Content-Type: application/json" \
  -d "{\"fullName\":\"Alex\",\"email\":\"a@b.c\",\"bio\":\"1' OR 1=1--\"}" \
  http://localhost:8090/api/users

# Clean origin API — proxied to user-testing
curl -i -H "Host: usertesting.singamsettikrishna.in" http://localhost:8090/api/users

# SQL Injection against the diagnostic gateway on the control-plane host
curl -i "http://localhost:8090/api/traffic/gateway?domain=usertesting.singamsettikrishna.in&payload=1'%20OR%201=1--"

# Remote Code Execution (RCE)
curl -i "http://localhost:8090/api/traffic/gateway?domain=singamsettikrishna.in&payload=;cat%20/etc/passwd"

# Cross-Site Scripting (XSS)
curl -i "http://localhost:8090/api/traffic/gateway?domain=singamsettikrishna.in&payload=<script>alert('XSS')</script>"
```
