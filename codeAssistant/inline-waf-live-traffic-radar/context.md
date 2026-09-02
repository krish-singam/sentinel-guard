# Feature: inline-waf-live-traffic-radar

## User request (verbatim)

> so i have sentinel-guard
>
> we have to improve this, whatever the domains got added and the A record of sentinel-guard is added in those domains, intercept all the headers, payload (in any format) and check for all the vulnerabilities we've implemented
>
> and rador them

Interpreted as: **Threat Radar** (existing dashboard tab), not a new product named “rador”.

## Objective

When a domain is registered in SentinelGuard **and** its DNS **A record points at SentinelGuard’s public IP**, every inbound HTTP request for that Host must be:

1. Intercepted (headers + body, any common payload format)
2. Inspected by **all** existing WAF detectors
3. Blocked if malicious
4. Recorded as a `SecurityIncident` so it appears on **Threat Radar** (`/api/dashboard/live-feed` + radar UI)

## Confirmed current architecture

| Layer | What exists today |
|---|---|
| Domain inventory | `MonitoredDomain` + `DomainController` add/list/refresh/delete |
| DNS intelligence | `DnsLookupService` resolves A/AAAA/MX/TXT/NS/CNAME and stores `primaryIp` |
| Live WAF filter | `WafTrafficInspectionFilter` (highest precedence, before Spring Security) |
| Detectors | SQLi, XSS, RCE, Path Traversal, SSRF, XXE, SSTI, NoSQL/LDAP, Deserialization, CRLF + DDoS rate-limit + scanner UA |
| Radar | `DashboardController.getLiveIncidents` + `index.html` tab `radar` |
| Public traffic stub | `TrafficGatewayController` at `/api/traffic/**` and `/gateway/**` — returns JSON, does **not** reverse-proxy |
| Nginx | `server_name sentinel-guard.singamsettikrishna.in` only (OCI guide also has a `usertesting` vhost → `:8090`) |
| Seeded domains | `sentinel-guard.singamsettikrishna.in`, `usertesting.singamsettikrishna.in`, `singamsettikrishna.in` — all listed at `140.245.250.50` |

Related origin app in the workspace: `user-testing` (port 8085 locally / 8080 in Docker), currently a separate nginx vhost, not inspected by SentinelGuard unless traffic is sent to SentinelGuard itself.

## Gaps (why this feature is needed)

1. **Only stub paths are public data-plane.** Spring Security permits `/api/traffic/**` and `/gateway/**`. Any other Host/path (`/`, `/api/users`, JSON POST to a customer API) hits `anyRequest().authenticated()` → 401, so real domain traffic never reaches a WAF-pass-through.
2. **Filter treats `/` and `/index.html` as SentinelGuard static UI.** A request to `https://usertesting.singamsettikrishna.in/` with Host `usertesting...` would skip WAF and serve the SentinelGuard dashboard, not inspect customer traffic.
3. **A-record is not a protection gate.** `primaryIp` is stored for display. There is no check that the domain’s A record actually equals SentinelGuard’s own IP before treating the Host as inline-protected.
4. **Body inspection is a single UTF-8 string.** No JSON tree walk, XML text/attributes, `application/x-www-form-urlencoded` fields, or `multipart/form-data` parts. Nested / double-encoded / Base64-wrapped payloads can miss detectors.
5. **Radar attribution is incomplete.** Incidents use Host header as `domainName`, but `domainId` is never set. Domain request counters only increment on exact `findByDomainNameIgnoreCase(host)`.
6. **No origin reverse-proxy after a clean pass.** Filter comment mentions “proxy pipeline” but nothing forwards to `user-testing` or another origin.

## Implemented vulnerability detectors (must all run)

- `SqlInjectionDetector` — SQL_INJECTION
- `XssDetector` — XSS
- `RceDetector` — REMOTE_CODE_EXECUTION
- `PathTraversalDetector` — PATH_TRAVERSAL
- `SsrfDetector` — SSRF
- `XxeDetector` — XXE
- `SstiDetector` — SSTI
- `NoSqlLdapDetector` — NOSQL_INJECTION / LDAP_INJECTION
- `DeserializationDetector` — DESERIALIZATION_ATTACK
- `CrlfInjectionDetector` — CRLF_INJECTION
- `DdosRateLimiter` — DOS_HTTP_FLOOD
- Scanner UA check in `WafInspectionEngine` — SUSPICIOUS_SCANNER

`ThreatType` also lists `PROTOTYPE_POLLUTION`, `AUTH_BRUTE_FORCE`, `MALICIOUS_USER_AGENT` with **no dedicated detector** today. Out of scope unless requested.

## Confirmed (2026-09-02)

1. Origin after clean request: **reverse-proxy**. **`originUrl` stored per domain.**
2. API coverage: **complete APIs** — all methods and all origin paths, not `/api/traffic` only.
3. A-record: user already pointed **usertesting** DNS A at SentinelGuard’s IP. Inspect + proxy that Host.
4. Radar: existing Threat Radar. Persist incidents with `domainId`.
5. Nginx: catch-all / usertesting vhost must send Host to **:8090**. Disable user-testing nginx that proxies usertesting straight to :8080.
6. If traffic hits this box for a registered Host, inspect even if DNS cache is briefly stale. UI still shows A-record match as `INLINE` vs `DNS_PENDING`.
7. Payload formats v1: JSON (nested), XML, form-urlencoded, multipart, query, cookies, all headers, raw, one-level Base64. Not protobuf/gRPC.

## Assumptions still in force

1. Control-plane Host (`sentinel-guard.singamsettikrishna.in`, localhost) keeps dashboard + RBAC and is not reverse-proxied.
2. `singamsettikrishna.in` origin is left empty until set (do not guess).
3. user-testing app code is not modified.

## Files most relevant to this feature

- `src/main/java/com/krish/sentinel_guard/waf/filter/WafTrafficInspectionFilter.java`
- `src/main/java/com/krish/sentinel_guard/waf/filter/CachedBodyHttpServletRequest.java`
- `src/main/java/com/krish/sentinel_guard/waf/detector/WafInspectionEngine.java`
- `src/main/java/com/krish/sentinel_guard/config/SecurityConfig.java`
- `src/main/java/com/krish/sentinel_guard/controller/TrafficGatewayController.java`
- `src/main/java/com/krish/sentinel_guard/model/MonitoredDomain.java`
- `src/main/java/com/krish/sentinel_guard/service/DnsLookupService.java`
- `src/main/java/com/krish/sentinel_guard/controller/DashboardController.java`
- `src/main/resources/static/index.html` (Threat Radar)
- `nginx/sentinelguard.conf`
