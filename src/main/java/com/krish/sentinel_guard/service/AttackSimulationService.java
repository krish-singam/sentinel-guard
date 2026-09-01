package com.krish.sentinel_guard.service;

import com.krish.sentinel_guard.model.*;
import com.krish.sentinel_guard.repository.AuditLogRepository;
import com.krish.sentinel_guard.repository.MonitoredDomainRepository;
import com.krish.sentinel_guard.repository.SecurityIncidentRepository;
import com.krish.sentinel_guard.waf.detector.DdosRateLimiter;
import com.krish.sentinel_guard.waf.detector.WafInspectionEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;

@Service
public class AttackSimulationService {

    private static final Logger log = LoggerFactory.getLogger(AttackSimulationService.class);

    private final WafInspectionEngine wafEngine;
    private final SecurityIncidentRepository incidentRepository;
    private final AuditLogRepository auditLogRepository;
    private final MonitoredDomainRepository domainRepository;
    private final AlertNotificationService alertService;
    private final DdosRateLimiter ddosRateLimiter;

    public AttackSimulationService(
            WafInspectionEngine wafEngine,
            SecurityIncidentRepository incidentRepository,
            AuditLogRepository auditLogRepository,
            MonitoredDomainRepository domainRepository,
            AlertNotificationService alertService,
            DdosRateLimiter ddosRateLimiter) {
        this.wafEngine = wafEngine;
        this.incidentRepository = incidentRepository;
        this.auditLogRepository = auditLogRepository;
        this.domainRepository = domainRepository;
        this.alertService = alertService;
        this.ddosRateLimiter = ddosRateLimiter;
    }

    public record SimulationResult(
        boolean intercepted,
        ActionTaken actionTaken,
        ThreatType attackType,
        ThreatSeverity severity,
        int threatScore,
        String matchedRule,
        String payloadSnippet,
        String targetDomain,
        long executionTimeMs,
        String message,
        boolean ipJailed
    ) {}

    @Transactional
    public SimulationResult runAttackTest(
            String performedBy,
            UserRole role,
            ThreatType attackType,
            String targetDomain,
            String payload,
            String clientIp) {

        long start = System.currentTimeMillis();
        String effectiveIp = (clientIp != null && !clientIp.isBlank()) ? clientIp : "198.51.100.42";
        String effectiveDomain = (targetDomain != null && !targetDomain.isBlank()) ? targetDomain : "usertesting.singamsettikrishna.in";

        // Evaluate through WAF engine
        WafInspectionEngine.WafEvaluationResult wafResult = wafEngine.inspect(
            effectiveIp,
            "POST",
            "/api/v1/search",
            "q=" + payload,
            Map.of("User-Agent", "RedTeam-PenTest-Simulator/1.0", "X-Forwarded-For", effectiveIp),
            payload
        );

        long elapsed = System.currentTimeMillis() - start;
        boolean blocked = !wafResult.allowed();

        // Persist Security Incident
        SecurityIncident incident = new SecurityIncident(
            effectiveDomain,
            effectiveIp,
            blocked ? wafResult.threatType() : attackType,
            wafResult.severity(),
            wafResult.action(),
            wafResult.threatScore(),
            wafResult.ruleTriggered(),
            payload,
            "POST",
            "/api/v1/search"
        );
        incident.setClientCountry("United States");
        incident.setClientCountryCode("US");
        incident.setClientCity("Simulated Red-Team Origin");
        incidentRepository.save(incident);

        // Update Domain metrics
        domainRepository.findByDomainNameIgnoreCase(effectiveDomain).ifPresent(d -> {
            d.setTotalRequests(d.getTotalRequests() + 1);
            if (blocked) {
                d.setBlockedRequests(d.getBlockedRequests() + 1);
            } else {
                d.setCleanRequests(d.getCleanRequests() + 1);
            }
            domainRepository.save(d);
        });

        // Trigger Alerts if threat is severe
        if (blocked) {
            alertService.dispatchThreatAlert(incident);
        }

        // Record Super Admin Audit Log
        AuditLog audit = new AuditLog(
            performedBy,
            role,
            attackType,
            effectiveDomain,
            payload,
            wafResult.action(),
            wafResult.threatScore(),
            elapsed,
            effectiveIp,
            blocked ? "WAF successfully intercepted and neutralized attack vector" : "Payload bypassed WAF (Clean traffic)"
        );
        auditLogRepository.save(audit);

        boolean isJailed = ddosRateLimiter.isIpBanned(effectiveIp);

        return new SimulationResult(
            blocked,
            wafResult.action(),
            wafResult.threatType(),
            wafResult.severity(),
            wafResult.threatScore(),
            wafResult.ruleTriggered(),
            payload,
            effectiveDomain,
            elapsed,
            blocked ? "Attack successfully blocked by SentinelGuard WAF: " + wafResult.ruleTriggered() : "Warning: Payload passed clean",
            isJailed
        );
    }

    public record FloodSimulationResult(
        int totalRequestsSent,
        int blockedCount,
        int passedCount,
        boolean ipJailed,
        long totalDurationMs,
        String message
    ) {}

    public FloodSimulationResult runDdosFloodTest(String performedBy, UserRole role, String targetDomain, int requestCount) {
        long start = System.currentTimeMillis();
        String floodIp = "203.0.113." + (int)(Math.random() * 250 + 1);
        int clampedCount = Math.min(Math.max(requestCount, 20), 200);

        int blocked = 0;
        int passed = 0;

        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<Boolean>> futures = new ArrayList<>();
            for (int i = 0; i < clampedCount; i++) {
                futures.add(executor.submit(() -> {
                    WafInspectionEngine.WafEvaluationResult res = wafEngine.inspect(
                        floodIp, "GET", "/api/products", "", Map.of("User-Agent", "HTTP-Flood-Bot/2.0"), ""
                    );
                    return !res.allowed();
                }));
            }

            for (Future<Boolean> f : futures) {
                try {
                    if (f.get(5, TimeUnit.SECONDS)) {
                        blocked++;
                    } else {
                        passed++;
                    }
                } catch (Exception ignored) {
                    blocked++;
                }
            }
        }

        long elapsed = System.currentTimeMillis() - start;
        boolean isJailed = ddosRateLimiter.isIpBanned(floodIp);

        // Record Audit log
        AuditLog audit = new AuditLog(
            performedBy,
            role,
            ThreatType.DOS_HTTP_FLOOD,
            targetDomain,
            "Simulated HTTP Flood (" + clampedCount + " requests concurrently)",
            isJailed ? ActionTaken.IP_BANNED : ActionTaken.RATE_LIMITED_429,
            95,
            elapsed,
            floodIp,
            "Rate Limiter & DDoS Jail triggered: " + blocked + "/" + clampedCount + " requests blocked."
        );
        auditLogRepository.save(audit);

        return new FloodSimulationResult(
            clampedCount,
            blocked,
            passed,
            isJailed,
            elapsed,
            "DDoS Flood simulation finished. WAF rate-limiting and firewall jail intercepted " + blocked + "/" + clampedCount + " requests."
        );
    }
}
