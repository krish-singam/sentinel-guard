# HLD: inline-waf-live-traffic-radar

## Overview

SentinelGuard is now an inline reverse-proxy WAF for registered domains whose DNS A record points at the WAF IP. `usertesting.singamsettikrishna.in` is onboarded with a per-domain `originUrl`. Every HTTP method and path for that Host is unpacked (headers, query, JSON, XML, form, multipart), scanned by all existing detectors, blocked onto Threat Radar if malicious, or forwarded to origin if clean.

## File / function changes

| File | Change |
|---|---|
| `MonitoredDomain` | `originUrl`, `dnsPointsToWaf`, `wafProtectionStatus` |
| `DomainController` | POST originUrl; PUT update origin |
| `DomainIntelligenceService` | A-record vs WAF IP; protection status |
| `WafPublicIdentityService` | Compare DNS to `sentinel.waf.public-ip` |
| `OriginUrlValidator` | http(s) only; block metadata hosts |
| `PayloadNormalizer` | Unpack inspectable surfaces |
| `WafInspectionEngine.inspectSurfaces` | All detectors on every surface |
| `WafTrafficInspectionFilter` | Control-plane vs data-plane Host routing |
| `OriginProxyService` | Forward method/path/query/headers/body |
| `SecurityConfig` | permitAll for protected-domain Hosts |
| `DataInitializer` | Seed/patch usertesting origin |
| `nginx/sentinelguard.conf` | usertesting + default_server → :8090 |
| `index.html` | Origin URL field; INLINE badge |
| Tests | Normalizer, origin URL, A-record, SQLi/XSS/RCE surfaces |

## Design decisions

- Filter-level proxy avoids Spring MVC `/**` colliding with the dashboard.
- Control-plane Host (`localhost`, `sentinel-guard.*`) still serves the SOC UI.
- Data-plane Hosts never render the SentinelGuard dashboard; `/` is proxied to origin.
- First detector match still wins (latency). Every detector still runs on every surface until a hit.
- Origin down → 502, not a radar incident.

## Edge cases

- Unknown Host → 404 JSON
- Protected domain with blank origin → 502 `NO_ORIGIN`
- Banned IP on data-plane → 403
- `www.` prefix stripped when matching inventory
- Invalid origin URL on add/update → 400
- Nginx vhost that still points usertesting at :8080 bypasses the WAF and must be removed

## Traffic path (usertesting)

```
Host: usertesting.singamsettikrishna.in
  → nginx :80/:443 → 127.0.0.1:8090
  → WafTrafficInspectionFilter
      → PayloadNormalizer → all ThreatDetectors
      → attack: 403 + SecurityIncident (Threat Radar)
      → clean: OriginProxyService → originUrl (local http://127.0.0.1:8085)
```
