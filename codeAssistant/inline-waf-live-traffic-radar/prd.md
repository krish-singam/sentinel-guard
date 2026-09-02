# PRD & Implementation Plan: inline-waf-live-traffic-radar

## Confirmed product decisions (2026-09-02)

| Decision | Choice |
|---|---|
| Origin after clean request | Reverse-proxy to a **per-domain `originUrl`** |
| API coverage | **Complete APIs** — every HTTP method and every path of the origin (`GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS`), not the `/api/traffic` stub |
| A-record | `usertesting.singamsettikrishna.in` already points at SentinelGuard’s IP. Treat registered Host + A-record-to-WAF as inline protection. Inspect any registered Host that actually hits this box even if DNS cache is stale |
| Radar | Existing Threat Radar live feed + charts. Persist `SecurityIncident` with `domainId` |
| Control plane | `sentinel-guard.singamsettikrishna.in` / `localhost` keep dashboard + RBAC. Do not reverse-proxy those Hosts |

---

## 1. Goal

When a domain is in inventory (e.g. `usertesting.singamsettikrishna.in`) and its DNS **A record points at SentinelGuard**, every inbound request for that Host is:

1. Intercepted (all headers + payload in JSON / XML / form / multipart / query / cookies / raw)
2. Scanned by **all implemented detectors**
3. **403 + radar** if malicious
4. **Reverse-proxied to `originUrl`** if clean (full origin API surface)

```
Browser  →  usertesting.singamsettikrishna.in  (A → 140.245.250.50)
                │
                ▼
         Nginx (Host-based, catch-all → :8090)
                │
                ▼
         SentinelGuard WAF filter
           ├─ attack → 403 JSON + SecurityIncident → Threat Radar
           └─ clean  → HttpClient → originUrl (user-testing :8085 local / :8080 Docker)
```

---

## 2. Files to create

### `src/main/java/com/krish/sentinel_guard/waf/payload/PayloadSurface.java`
- **Purpose:** One inspectable string with a location label.
- **Fields:** `String location`, `String value`
- **I/O:** Immutable record.

### `src/main/java/com/krish/sentinel_guard/waf/payload/PayloadNormalizer.java`
- **Purpose:** Unpack any common HTTP payload into surfaces for detectors.
- **Input:** path, queryString, `Map<String,String>` headers, raw body bytes, `Content-Type`, charset
- **Output:** `List<PayloadSurface>`
- **Behavior:**
  - Always include: URI path (raw + URL-decoded + double-decoded), full query string, each query param name/value, each header name/value, each Cookie name/value
  - Body:
    - `application/json` / `application/problem+json` / `application/vnd.api+json`: Jackson walk — every key and every string/number/boolean leaf
    - `application/xml` / `text/xml` / `application/soap+xml`: full document + element text + attribute values (StAX or regex-safe string extract; no XXE entity expansion — disable DTD)
    - `application/x-www-form-urlencoded`: each field
    - `multipart/form-data`: each part filename + text body (skip obvious binary images except UTF-8 attempt + Java serialization magic `aced` / `rO0AB`)
    - `text/*`, `application/graphql`, `application/javascript`, `application/x-www-form-urlencoded`: full text
    - unknown / `application/octet-stream`: UTF-8 string if mostly text; always scan for deserialization magic bytes
  - If a value looks like Base64 (length ≥ 16, charset match), decode once and add a `Base64[...]` surface
  - Always also include raw body as `HTTP Request Body`
- **Does not:** parse protobuf schemas or gRPC frames

### `src/main/java/com/krish/sentinel_guard/service/WafPublicIdentityService.java`
- **Purpose:** Know “our” WAF IPs for A-record matching.
- **Config:** `sentinel.waf.public-ip` (default `140.245.250.50`), optional `sentinel.waf.public-ipv6`
- **Method:** `boolean pointsToWaf(List<String> aRecords, List<String> aaaaRecords)`
- **Also:** treat `127.0.0.1` / `::1` as WAF in local profile so local Host testing works

### `src/main/java/com/krish/sentinel_guard/service/OriginProxyService.java`
- **Purpose:** Forward a clean request to `originUrl` and copy the origin response.
- **Input:** `CachedBodyHttpServletRequest`, `HttpServletResponse`, `originUrl` (absolute, e.g. `http://127.0.0.1:8085`)
- **Output:** void (writes status/headers/body to servlet response)
- **Forward:** method, path, query string, body bytes, headers except hop-by-hop (`Connection`, `Keep-Alive`, `Transfer-Encoding`, `TE`, `Trailer`, `Upgrade`, `Proxy-Authorization`, `Content-Length` — length is set from cached body)
- **Host header:** original customer Host (so origin virtual-hosts still work)
- **Add:** `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Real-IP`
- **Timeouts:** 60s connect/read (match nginx)
- **Client:** JDK `HttpClient` (virtual threads)
- **Errors:** origin down → 502 JSON `{ "error": "Origin unreachable", "wafEngine": "SentinelGuard..." }` (not a radar incident unless we choose to log as health — **no incident** for origin down)
- **Not forwarded:** WebSocket upgrade (return 501) — out of scope

### `src/test/java/com/krish/sentinel_guard/waf/payload/PayloadNormalizerTest.java`
- Nested JSON SQLi in `"bio"` is extracted
- Form field XSS extracted
- Multipart text part extracted
- Query param path-traversal extracted

### `src/test/java/com/krish/sentinel_guard/waf/detector/WafInspectionEngineSurfaceTest.java`
- JSON body `{"fullName":"1' OR 1=1--"}` → SQL_INJECTION
- Header `Referer` XSS → XSS
- Multipart RCE string → REMOTE_CODE_EXECUTION

---

## 3. Files to modify

### `model/MonitoredDomain.java`
**Add:**
- `String originUrl` — e.g. `http://127.0.0.1:8085`
- `Boolean dnsPointsToWaf` — last A/AAAA match vs WAF public IP
- `String wafProtectionStatus` — `INLINE` | `DNS_PENDING` | `NO_ORIGIN` | `CONTROL_PLANE`

JPA `ddl-auto=update` adds columns. No migration script.

### `controller/DomainController.java`
**Change `AddDomainRequest`:**
```
domainName, displayName, originUrl
```
**Add:**
- `PUT /api/domains/{id}` — update `displayName`, `originUrl`, `isProtected`
- Response DTOs already return the entity; new fields appear on GET `/api/domains` automatically

### `service/DomainIntelligenceService.java`
- `registerDomain(...)` accepts `originUrl`, sanitizes (`http://` or `https://` only, no `file:`)
- `refreshDomainIntelligence`: after DNS lookup, set `dnsPointsToWaf` via `WafPublicIdentityService`; set `wafProtectionStatus`
- Seed/update existing rows: if `originUrl` blank, leave blank except usertesting seed

### `config/DataInitializer.java`
- `usertesting.singamsettikrishna.in`: `originUrl=http://127.0.0.1:8085` (override with `sentinel.waf.seed.usertesting-origin`)
- On **existing** DBs (`count() > 0`): if usertesting row has null origin, patch origin once (idempotent) so current H2/Postgres installs get the field
- `sentinel-guard.singamsettikrishna.in`: `wafProtectionStatus=CONTROL_PLANE`, no origin
- `singamsettikrishna.in`: origin left empty until user sets it (do not guess)

### `config/SecurityConfig.java`
- Keep current RBAC for **control-plane Hosts**
- **Permit all** for data-plane: requests whose Host (minus port) is a registered non-control-plane domain
  - Implementation: `RequestMatcher` `ProtectedDomainHostMatcher` that looks up `MonitoredDomainRepository` (cache Host → domain, TTL ~30s, invalidate on add/delete)
- Control-plane Hosts: `localhost`, `127.0.0.1`, values in `sentinel.waf.control-plane-hosts` (default `sentinel-guard.singamsettikrishna.in`)
- OPTIONS still permitAll

### `waf/filter/WafTrafficInspectionFilter.java` (core rewrite of routing, not detectors)

```
doFilterInternal:
  host = resolveHostDomain(request)

  if isControlPlaneHost(host):
      current skip list for /api/dashboard, /api/auth, static UI
      chain.doFilter
      return

  domain = findRegisteredDomain(host)  // exact, then strip www.
  if domain is empty OR isProtected == false:
      404 JSON "Unknown or unprotected host"
      return

  // banned IP check (existing)
  wrap CachedBodyHttpServletRequest
  collect ALL headers (existing)
  contentType = request.getContentType()
  surfaces = payloadNormalizer.normalize(path, query, headers, bodyBytes, contentType)

  eval = wafEngine.inspectSurfaces(clientIp, method, surfaces)

  if !eval.allowed():
      persist SecurityIncident with domainId + domainName
      alert, metrics, optional jail
      403 WAF JSON
      return

  metrics clean++
  if originUrl blank:
      502 JSON "No originUrl configured"
      return
  originProxyService.forward(cachedRequest, response, domain.originUrl)
```

**Do not** treat `/` as static UI when Host is a customer domain.

### `waf/detector/WafInspectionEngine.java`
**Add:**
```
inspectSurfaces(clientIp, method, List<PayloadSurface> surfaces)
```
- Rate-limit first (existing)
- For **each** surface, run **every** `ThreatDetector` (same order as today)
- First detection → blocked result with location in `reason` (`Threat detected in JSON field [bio] ...`)
- Keep `inspect(...)` for Attack Simulation (build surfaces from path/query/headers/body internally so sim still works)

### `controller/TrafficGatewayController.java`
- Retire as the data-plane. Leave `/api/traffic/**` only as a **control-plane diagnostic** on the SentinelGuard Host (optional ping). Customer Hosts never hit this controller — the filter proxies instead.

### `controller/DashboardController.java`
- No contract change. Incidents already power radar. Ensure `domainId` is populated so domain filter stays accurate.

### `model/SecurityIncident.java`
- Filter already sets domainName; **set `domainId`** from `MonitoredDomain.getId()`
- Set `queryString` field separately (today path concatenates query)

### `src/main/resources/application.properties` (+ prod)
```
sentinel.waf.public-ip=${SENTINEL_WAF_PUBLIC_IP:140.245.250.50}
sentinel.waf.control-plane-hosts=${SENTINEL_CONTROL_PLANE_HOSTS:sentinel-guard.singamsettikrishna.in}
sentinel.waf.seed.usertesting-origin=${SENTINEL_USERTESTING_ORIGIN:http://127.0.0.1:8085}
spring.servlet.multipart.max-file-size=50MB
spring.servlet.multipart.max-request-size=50MB
```

### `docker-compose.yml`
```
extra_hosts:
  - "host.docker.internal:host-gateway"
```
Prod seed origin for usertesting when running in Docker should be `http://host.docker.internal:8080` (user-testing container published on host). Override via `SENTINEL_USERTESTING_ORIGIN`.

### `nginx/sentinelguard.conf`
- Keep SSL vhost for `sentinel-guard.singamsettikrishna.in`
- **Add** HTTP+HTTPS (or HTTP catch-all) `default_server` / `server_name usertesting.singamsettikrishna.in` that `proxy_pass` **8090**, not origin 8080
- Document: **disable** `user-testing/nginx-subdomain.conf` on the VM if it still sends `usertesting` straight to `:8080` (that bypasses the WAF)

### `src/main/resources/static/index.html`
- Add Domain modal: **Origin URL** input (required for data-plane), placeholder `http://127.0.0.1:8085`
- Domain card: show `originUrl`, badge `INLINE` if `dnsPointsToWaf` else `DNS_PENDING`
- Domain details modal: same fields
- `submitAddDomain` POSTs `{ domainName, displayName, originUrl }`
- Radar: no new tab; live feed already polls `/api/dashboard/live-feed`. Confirm table shows domain `usertesting.singamsettikrishna.in` for live blocks

### `config/DataInitializer.java` + README / OCI guide
- Document Hostinger A record (already done by user)
- Nginx must send `usertesting` Host to 8090
- Origin of user-testing remains 8080 on loopback

---

## 4. Control / data flow

```
Request Host
    │
    ├─ control-plane Host? ──► Spring Security RBAC ──► dashboard / APIs
    │
    └─ registered domain Host?
            ├─ no ──► 404
            ├─ banned IP ──► 403 + radar
            ├─ PayloadNormalizer ──► all surfaces
            ├─ all ThreatDetectors + DDoS
            ├─ hit ──► SecurityIncident(domainId) ──► live-feed ──► Threat Radar
            └─ clean ──► OriginProxyService ──► originUrl + original path/query/body/headers
```

**Complete origin APIs (user-testing) that must pass when clean and block when poisoned:**

| Method | Path |
|---|---|
| GET | `/` (SPA) |
| GET | `/api/users` |
| GET | `/api/users/{id}` |
| POST | `/api/users` (JSON) |
| PUT | `/api/users/{id}` (JSON) |
| PATCH | `/api/users/{id}/status` |
| DELETE | `/api/users/{id}` |
| GET | `/api/users/stats` |
| GET | `/api/users/departments` |
| GET | `/api/users/meta/roles` |
| GET | `/api/users/meta/statuses` |
| OPTIONS | `/**` (CORS preflight — inspect, then forward) |

Any other path the origin adds later is covered by catch-all proxy.

---

## 5. Design rationale

- **Filter-level proxy** avoids Spring MVC mapping wars (`/**` vs `/api/dashboard`) and avoids 401 on customer APIs.
- **Per-domain originUrl** matches multiple apps (user-testing now; portfolio later) without a global backend.
- **A-record flag** is operational truth for the UI; inspection still runs if the Host hits this box (user already pointed usertesting here).
- **PayloadNormalizer** is the actual “any format” work; detectors stay regex-on-string.
- **First detector hit still wins** for latency. Every detector still **runs on every surface until one fires** — same coverage as “check all vulnerabilities,” not a new detector family.

---

## 6. Impact

| Area | Impact |
|---|---|
| Attack Simulation | Unchanged; engine `inspect()` still used |
| Threat Radar | More real incidents with correct `domainId` / Host |
| user-testing nginx | **Must not** steal `server_name usertesting` to :8080 on the same VM |
| SentinelGuard dashboard | Only on control-plane Host |
| Docker | Needs `host.docker.internal` to reach origin on host port 8080 |
| SSL | Existing Let’s Encrypt cert for usertesting can stay on nginx; nginx terminates TLS, HTTP to 8090 |

---

## 7. Risks / trade-offs

| Risk | Mitigation |
|---|---|
| False positives on headers (Referer with `../`) | Accept; same as current engine |
| Large multipart (50MB) buffered in memory | Same as current `CachedBodyHttpServletRequest`; keep 50MB cap |
| Origin URL SSRF by admin (`http://169.254.169.254`) | Sanitize: only `http`/`https`; block link-local/metadata IPs in originUrl |
| Two nginx vhosts for usertesting | Document disable origin-direct vhost |
| `application-prod.properties` `server.port=8080` vs docker `8090:8090` | Do not change ports in this feature unless already mapped; proxy uses 8090 as today |
| Host cache stale after add-domain | Evict cache on register/delete |

---

## 8. Testing strategy

**Unit**
- `PayloadNormalizerTest` — JSON / form / multipart / query / Base64
- `WafPublicIdentityService` — A record `140.245.250.50` → true
- Origin URL sanitizer — reject `file:///`, `http://169.254.169.254`

**Integration (Spring Boot test, MockMvc or TestRestTemplate)**
- Host `usertesting.singamsettikrishna.in` + `GET /api/users` + mocked origin → 200 from stub origin
- Same Host + POST JSON SQLi → 403, row in `security_incidents`, `domainName=usertesting...`
- Host `localhost` + `GET /api/dashboard/stats` still 401 without basic auth
- Header XSS (`User-Agent` / custom header) → 403 + radar
- Form-urlencoded XSS → 403

**Manual / browser**
- Open `http://usertesting.../` (hosts file or real DNS) → user-testing SPA, not SentinelGuard UI
- POST malicious JSON to `/api/users` → 403
- Threat Radar shows the incident within poll interval
- Clean CRUD still works

---

## 9. Out of scope

- New detector types (prototype pollution dedicated, brute force)
- Automatic Let’s Encrypt for every new domain
- WebSocket / gRPC / HTTP/2 trailers
- Changing user-testing application code

---

## 10. Success criteria

1. Request to `usertesting.singamsettikrishna.in` with any of the origin APIs is inspected.
2. Payloads in JSON, form, query, headers, and multipart are unpacked and scanned by all current detectors.
3. Attacks return 403 and appear on Threat Radar under that domain.
4. Clean requests reach user-testing via `originUrl` and return origin status/body.
5. SentinelGuard dashboard Host is unchanged (login + radar UI).
