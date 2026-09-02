package com.krish.sentinel_guard.waf.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.krish.sentinel_guard.model.*;
import com.krish.sentinel_guard.repository.BannedIpRepository;
import com.krish.sentinel_guard.repository.MonitoredDomainRepository;
import com.krish.sentinel_guard.repository.SecurityIncidentRepository;
import com.krish.sentinel_guard.service.AlertNotificationService;
import com.krish.sentinel_guard.service.DomainIntelligenceService;
import com.krish.sentinel_guard.service.GeoIpService;
import com.krish.sentinel_guard.service.OriginProxyService;
import com.krish.sentinel_guard.service.WafHostClassificationService;
import com.krish.sentinel_guard.waf.detector.WafInspectionEngine;
import com.krish.sentinel_guard.waf.payload.PayloadNormalizer;
import com.krish.sentinel_guard.waf.payload.PayloadSurface;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Inline WAF for every Host that resolves to this box (any DNS provider).
 * Control-plane Hosts serve the dashboard. Data-plane Hosts are inspected
 * then reverse-proxied to the domain's originUrl when configured.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class WafTrafficInspectionFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(WafTrafficInspectionFilter.class);

    private final WafInspectionEngine wafEngine;
    private final SecurityIncidentRepository incidentRepository;
    private final MonitoredDomainRepository domainRepository;
    private final BannedIpRepository bannedIpRepository;
    private final AlertNotificationService alertService;
    private final GeoIpService geoIpService;
    private final WafHostClassificationService hostClassification;
    private final DomainIntelligenceService domainIntelligenceService;
    private final PayloadNormalizer payloadNormalizer;
    private final OriginProxyService originProxyService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public WafTrafficInspectionFilter(
            WafInspectionEngine wafEngine,
            SecurityIncidentRepository incidentRepository,
            MonitoredDomainRepository domainRepository,
            BannedIpRepository bannedIpRepository,
            AlertNotificationService alertService,
            GeoIpService geoIpService,
            WafHostClassificationService hostClassification,
            DomainIntelligenceService domainIntelligenceService,
            PayloadNormalizer payloadNormalizer,
            OriginProxyService originProxyService) {
        this.wafEngine = wafEngine;
        this.incidentRepository = incidentRepository;
        this.domainRepository = domainRepository;
        this.bannedIpRepository = bannedIpRepository;
        this.alertService = alertService;
        this.geoIpService = geoIpService;
        this.hostClassification = hostClassification;
        this.domainIntelligenceService = domainIntelligenceService;
        this.payloadNormalizer = payloadNormalizer;
        this.originProxyService = originProxyService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();
        String method = request.getMethod();
        String queryString = request.getQueryString();
        String clientIp = resolveClientIp(request);
        String hostDomain = hostClassification.resolveHost(request);

        if (hostClassification.isControlPlaneHost(hostDomain)) {
            if (isInternalControlPlaneApi(path) || (isStaticResource(path) && (queryString == null || queryString.trim().isEmpty()))) {
                filterChain.doFilter(request, response);
                return;
            }
            CachedBodyHttpServletRequest cachedRequest = new CachedBodyHttpServletRequest(request);
            WafInspectionEngine.WafEvaluationResult eval = inspectRequest(cachedRequest, clientIp, method, path, queryString);
            if (!eval.allowed()) {
                recordAndBlock(request, response, eval, clientIp, hostDomain, path, queryString, method, null);
                return;
            }
            filterChain.doFilter(cachedRequest, response);
            return;
        }

        MonitoredDomain domain = hostClassification.findDomain(hostDomain).orElse(null);
        if (domain == null && !hostClassification.looksLikeLiteralIp(hostDomain)) {
            try {
                domain = domainIntelligenceService.ensureInboundHost(hostDomain);
            } catch (IllegalArgumentException e) {
                domain = null;
            }
        }

        Optional<BannedIp> activeBan = bannedIpRepository.findByIpAddressAndActiveTrue(clientIp);
        if (activeBan.isPresent()) {
            BannedIp ban = activeBan.get();
            if (ban.getBannedUntil().isAfter(LocalDateTime.now())) {
                log.warn("WAF BLOCKED: Banned IP {} tried accessing {} on {}", clientIp, path, hostDomain);
                writeWafBlockResponse(response, 403, "IP_BANNED", "Client IP address is jailed in firewall jail",
                        ban.getReason(), clientIp, hostDomain);
                return;
            } else {
                ban.setActive(false);
                bannedIpRepository.save(ban);
            }
        }

        CachedBodyHttpServletRequest cachedRequest = new CachedBodyHttpServletRequest(request);
        WafInspectionEngine.WafEvaluationResult eval = inspectRequest(cachedRequest, clientIp, method, path, queryString);

        if (!eval.allowed()) {
            recordAndBlock(request, response, eval, clientIp, hostDomain, path, queryString, method, domain);
            return;
        }

        if (domain != null) {
            updateDomainMetrics(domain.getId(), true);
        }

        String originUrl = domain != null ? domain.getOriginUrl() : null;
        if (originUrl == null || originUrl.isBlank()) {
            writeWafBlockResponse(response, 502, "NO_ORIGIN",
                    "No originUrl configured for this domain",
                    "RULE_NO_ORIGIN", clientIp, hostDomain);
            return;
        }

        try {
            originProxyService.forward(cachedRequest, response, originUrl);
        } catch (Exception e) {
            log.warn("Origin proxy failed for {} -> {}: {}", hostDomain, originUrl, e.getMessage());
            writeWafBlockResponse(response, 502, "ORIGIN_UNREACHABLE",
                    "Origin backend is unreachable: " + originUrl,
                    "RULE_ORIGIN_DOWN", clientIp, hostDomain);
        }
    }

    private WafInspectionEngine.WafEvaluationResult inspectRequest(
            CachedBodyHttpServletRequest cachedRequest,
            String clientIp,
            String method,
            String path,
            String queryString) {
        Map<String, String> headers = collectHeaders(cachedRequest);
        List<PayloadSurface> surfaces = payloadNormalizer.normalize(
                path,
                queryString,
                headers,
                cachedRequest.getCachedBody(),
                cachedRequest.getContentType(),
                cachedRequest.getCachedCharacterEncoding()
        );
        return wafEngine.inspectSurfaces(clientIp, method, surfaces);
    }

    private void recordAndBlock(
            HttpServletRequest request,
            HttpServletResponse response,
            WafInspectionEngine.WafEvaluationResult eval,
            String clientIp,
            String hostDomain,
            String path,
            String queryString,
            String method,
            MonitoredDomain domain) throws IOException {

        log.warn("WAF INTERCEPTED ATTACK: Type={} | Rule={} | Target={} | IP={} | Path={}",
                eval.threatType(), eval.ruleTriggered(), hostDomain, clientIp, path);

        GeoIpService.GeoLocation geo = geoIpService.resolve(clientIp);

        SecurityIncident incident = new SecurityIncident(
                hostDomain,
                clientIp,
                eval.threatType(),
                eval.severity(),
                eval.action(),
                eval.threatScore(),
                eval.ruleTriggered(),
                eval.matchedSnippet(),
                method,
                path + (queryString != null ? "?" + queryString : "")
        );
        if (domain != null) {
            incident.setDomainId(domain.getId());
        }
        incident.setQueryString(queryString);
        incident.setClientCountry(geo.country());
        incident.setClientCountryCode(geo.countryCode());
        incident.setClientCity(geo.city());
        incident.setUserAgent(request.getHeader("User-Agent"));
        incident.setTimestamp(LocalDateTime.now());

        SecurityIncident saved = incidentRepository.save(incident);

        try {
            alertService.dispatchThreatAlert(saved);
        } catch (Exception e) {
            log.debug("Alert dispatch error: {}", e.getMessage());
        }

        if (domain != null) {
            updateDomainMetrics(domain.getId(), false);
        }

        if (eval.action() == ActionTaken.IP_BANNED) {
            jailOffendingIp(clientIp, geo.country(), eval.reason(), eval.threatType());
        }

        writeWafBlockResponse(response, 403, eval.action().name(), eval.reason(),
                eval.ruleTriggered(), clientIp, hostDomain);
    }

    private Map<String, String> collectHeaders(HttpServletRequest request) {
        Map<String, String> headers = new HashMap<>();
        Enumeration<String> headerNames = request.getHeaderNames();
        if (headerNames != null) {
            while (headerNames.hasMoreElements()) {
                String name = headerNames.nextElement();
                headers.put(name, request.getHeader(name));
            }
        }
        return headers;
    }

    private String resolveClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.trim().isEmpty()) {
            return xff.split(",")[0].trim();
        }
        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.trim().isEmpty()) {
            return realIp.trim();
        }
        return request.getRemoteAddr();
    }

    private boolean isStaticResource(String path) {
        return path.startsWith("/css/") ||
               path.startsWith("/js/") ||
               path.startsWith("/images/") ||
               path.equals("/favicon.ico") ||
               path.equals("/") ||
               path.equals("/index.html") ||
               path.startsWith("/h2-console");
    }

    private boolean isInternalControlPlaneApi(String path) {
        return path.startsWith("/api/simulation") ||
               path.startsWith("/api/dashboard") ||
               path.startsWith("/api/firewall") ||
               path.startsWith("/api/domains") ||
               path.startsWith("/api/incidents") ||
               path.startsWith("/api/reports") ||
               path.startsWith("/api/audit") ||
               path.startsWith("/api/auth");
    }

    private void updateDomainMetrics(Long domainId, boolean clean) {
        Thread.ofVirtual().start(() -> {
            try {
                domainRepository.findById(domainId).ifPresent(d -> {
                    d.setTotalRequests((d.getTotalRequests() != null ? d.getTotalRequests() : 0) + 1);
                    if (clean) {
                        d.setCleanRequests((d.getCleanRequests() != null ? d.getCleanRequests() : 0) + 1);
                    } else {
                        d.setBlockedRequests((d.getBlockedRequests() != null ? d.getBlockedRequests() : 0) + 1);
                    }
                    domainRepository.save(d);
                });
            } catch (Exception e) {
                log.debug("Failed to update domain metrics: {}", e.getMessage());
            }
        });
    }

    private void jailOffendingIp(String ip, String country, String reason, ThreatType threatType) {
        Thread.ofVirtual().start(() -> {
            try {
                if (bannedIpRepository.findByIpAddressAndActiveTrue(ip).isEmpty()) {
                    BannedIp ban = new BannedIp(ip, country != null ? country : "Unknown", reason, threatType, 1800);
                    bannedIpRepository.save(ban);
                    log.info("IP JAILED AUTOMATICALLY BY WAF FILTER: {}", ip);
                }
            } catch (Exception e) {
                log.debug("Auto-jail failed: {}", e.getMessage());
            }
        });
    }

    private void writeWafBlockResponse(HttpServletResponse response, int status, String action,
                                       String reason, String rule, String clientIp, String domain) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.setHeader("X-WAF-Protection", "SentinelGuard-Enterprise");
        response.setHeader("X-WAF-Action", action);
        response.setHeader("X-WAF-Rule", rule != null ? rule : "");

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", status);
        body.put("error", status == 403 ? "Forbidden - WAF Interception" : (status == 404 ? "Unknown host" : "Bad Gateway"));
        body.put("wafEngine", "SentinelGuard Intelligent WAF v1.0");
        body.put("actionTaken", action);
        body.put("reason", reason);
        body.put("matchedRule", rule);
        body.put("clientIp", clientIp);
        body.put("targetDomain", domain);
        body.put("timestamp", LocalDateTime.now().toString());

        response.getWriter().write(objectMapper.writeValueAsString(body));
    }
}
