package com.krish.sentinel_guard.waf.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.krish.sentinel_guard.model.*;
import com.krish.sentinel_guard.repository.BannedIpRepository;
import com.krish.sentinel_guard.repository.MonitoredDomainRepository;
import com.krish.sentinel_guard.repository.SecurityIncidentRepository;
import com.krish.sentinel_guard.service.AlertNotificationService;
import com.krish.sentinel_guard.service.GeoIpService;
import com.krish.sentinel_guard.waf.detector.WafInspectionEngine;
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
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.*;

/**
 * Real-time WAF Servlet Filter intercepting live incoming HTTP traffic
 * from external clients, reverse proxies, and direct domain hits.
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
    private final ObjectMapper objectMapper = new ObjectMapper();

    public WafTrafficInspectionFilter(
            WafInspectionEngine wafEngine,
            SecurityIncidentRepository incidentRepository,
            MonitoredDomainRepository domainRepository,
            BannedIpRepository bannedIpRepository,
            AlertNotificationService alertService,
            GeoIpService geoIpService) {
        this.wafEngine = wafEngine;
        this.incidentRepository = incidentRepository;
        this.domainRepository = domainRepository;
        this.bannedIpRepository = bannedIpRepository;
        this.alertService = alertService;
        this.geoIpService = geoIpService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();
        String method = request.getMethod();
        String queryString = request.getQueryString();

        // Extract client IP (handle proxies & load balancers)
        String clientIp = resolveClientIp(request);

        // Extract host domain name
        String hostDomain = resolveHostDomain(request);

        // 1. Check if client IP is currently jailed in Firewall
        Optional<BannedIp> activeBan = bannedIpRepository.findByIpAddressAndActiveTrue(clientIp);
        if (activeBan.isPresent()) {
            BannedIp ban = activeBan.get();
            if (ban.getBannedUntil().isAfter(LocalDateTime.now())) {
                log.warn("🛡️ WAF BLOCKED: Banned IP {} tried accessing {}", clientIp, path);
                writeWafBlockResponse(response, 403, "IP_BANNED", "Client IP address is jailed in firewall jail",
                        ban.getReason(), clientIp, hostDomain);
                return;
            } else {
                ban.setActive(false);
                bannedIpRepository.save(ban);
            }
        }

        // Allow bypassing internal asset loading if no query parameters exist
        if (isStaticResource(path) && (queryString == null || queryString.isEmpty())) {
            filterChain.doFilter(request, response);
            return;
        }

        // Allow internal authenticated API polling without query strings to avoid noise,
        // but ALWAYS inspect query strings, paths, and headers!
        if (isInternalDashboardPoll(path) && (queryString == null || queryString.isEmpty())) {
            filterChain.doFilter(request, response);
            return;
        }

        // 2. Collect Headers for Inspection
        Map<String, String> headers = new HashMap<>();
        Enumeration<String> headerNames = request.getHeaderNames();
        if (headerNames != null) {
            while (headerNames.hasMoreElements()) {
                String name = headerNames.nextElement();
                headers.put(name, request.getHeader(name));
            }
        }

        // Decode query string for accurate payload detection
        String decodedQuery = "";
        if (queryString != null) {
            try {
                decodedQuery = URLDecoder.decode(queryString, StandardCharsets.UTF_8);
            } catch (Exception e) {
                decodedQuery = queryString;
            }
        }

        // 3. Perform Deep WAF Packet Inspection
        WafInspectionEngine.WafEvaluationResult eval = wafEngine.inspect(
                clientIp, method, path, decodedQuery, headers, null
        );

        if (!eval.allowed()) {
            // Intercept and Block
            log.warn("🚨 WAF INTERCEPTED ATTACK: Type={} | Rule={} | Target={} | IP={}",
                    eval.threatType(), eval.ruleTriggered(), hostDomain, clientIp);

            // Resolve GeoIP location
            GeoIpService.GeoLocation geo = geoIpService.resolve(clientIp);

            // Record Security Incident in DB
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
            incident.setClientCountry(geo.country());
            incident.setClientCountryCode(geo.countryCode());
            incident.setClientCity(geo.city());
            incident.setUserAgent(request.getHeader("User-Agent"));
            incident.setTimestamp(LocalDateTime.now());

            SecurityIncident saved = incidentRepository.save(incident);

            // Trigger Alerts
            try {
                alertService.dispatchThreatAlert(saved);
            } catch (Exception e) {
                log.debug("Alert dispatch error: {}", e.getMessage());
            }

            // Update Domain Stats
            updateDomainMetrics(hostDomain, false);

            // If DoS or High-Severity repeatedly, Jail IP
            if (eval.action() == ActionTaken.IP_BANNED) {
                jailOffendingIp(clientIp, geo.country(), eval.reason(), eval.threatType());
            }

            // Return 403 Forbidden with WAF block signature
            writeWafBlockResponse(response, 403, eval.action().name(), eval.reason(),
                    eval.ruleTriggered(), clientIp, hostDomain);
            return;
        }

        // Clean request - record metrics
        updateDomainMetrics(hostDomain, true);

        // Proceed to application handler
        filterChain.doFilter(request, response);
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

    private String resolveHostDomain(HttpServletRequest request) {
        String host = request.getHeader("X-Forwarded-Host");
        if (host != null && !host.trim().isEmpty()) {
            return sanitizeHost(host);
        }
        host = request.getHeader("Host");
        if (host != null && !host.trim().isEmpty()) {
            return sanitizeHost(host);
        }
        return request.getServerName();
    }

    private String sanitizeHost(String host) {
        return host.split(":")[0].trim().toLowerCase();
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

    private boolean isInternalDashboardPoll(String path) {
        return path.equals("/api/dashboard/stats") ||
               path.equals("/api/dashboard/live-feed") ||
               path.equals("/api/dashboard/alerts") ||
               path.equals("/api/domains") ||
               path.equals("/api/firewall/banned-ips") ||
               path.equals("/api/reports/audit") ||
               path.equals("/api/auth/me") ||
               path.equals("/api/auth/roles") ||
               path.equals("/api/simulation/presets");
    }

    private void updateDomainMetrics(String hostDomain, boolean clean) {
        Thread.ofVirtual().start(() -> {
            try {
                Optional<MonitoredDomain> domainOpt = domainRepository.findByDomainNameIgnoreCase(hostDomain);
                if (domainOpt.isPresent()) {
                    MonitoredDomain d = domainOpt.get();
                    d.setTotalRequests((d.getTotalRequests() != null ? d.getTotalRequests() : 0) + 1);
                    if (clean) {
                        d.setCleanRequests((d.getCleanRequests() != null ? d.getCleanRequests() : 0) + 1);
                    } else {
                        d.setBlockedRequests((d.getBlockedRequests() != null ? d.getBlockedRequests() : 0) + 1);
                    }
                    domainRepository.save(d);
                }
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
                    log.info("🔒 IP JAILED AUTOMATICALLY BY WAF FILTER: {}", ip);
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
        response.setHeader("X-WAF-Rule", rule);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", status);
        body.put("error", "Forbidden - WAF Interception");
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
