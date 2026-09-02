package com.krish.sentinel_guard.waf.detector;

import com.krish.sentinel_guard.model.ActionTaken;
import com.krish.sentinel_guard.model.ThreatSeverity;
import com.krish.sentinel_guard.model.ThreatType;
import com.krish.sentinel_guard.waf.payload.PayloadNormalizer;
import com.krish.sentinel_guard.waf.payload.PayloadSurface;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Map;

@Service
public class WafInspectionEngine {

    private final List<ThreatDetector> detectors;
    private final DdosRateLimiter ddosRateLimiter;
    private final PayloadNormalizer payloadNormalizer;

    public WafInspectionEngine(
            List<ThreatDetector> detectors,
            DdosRateLimiter ddosRateLimiter,
            PayloadNormalizer payloadNormalizer) {
        this.detectors = detectors;
        this.ddosRateLimiter = ddosRateLimiter;
        this.payloadNormalizer = payloadNormalizer;
    }

    public record WafEvaluationResult(
        boolean allowed,
        ActionTaken action,
        ThreatType threatType,
        ThreatSeverity severity,
        int threatScore,
        String ruleTriggered,
        String matchedSnippet,
        String reason
    ) {
        public static WafEvaluationResult clean() {
            return new WafEvaluationResult(
                true,
                ActionTaken.PASSED_CLEAN,
                ThreatType.CLEAN,
                ThreatSeverity.INFO,
                0,
                "RULE_CLEAN_TRAFFIC",
                "",
                "Traffic verified clean by WAF deep inspection"
            );
        }

        public static WafEvaluationResult blocked(ThreatType type, ThreatSeverity severity, int score, String rule, String snippet, String reason) {
            return new WafEvaluationResult(
                false,
                ActionTaken.BLOCKED_403,
                type,
                severity,
                score,
                rule,
                snippet,
                reason
            );
        }

        public static WafEvaluationResult rateLimited(String reason, boolean isBanned) {
            return new WafEvaluationResult(
                false,
                isBanned ? ActionTaken.IP_BANNED : ActionTaken.RATE_LIMITED_429,
                ThreatType.DOS_HTTP_FLOOD,
                ThreatSeverity.CRITICAL,
                90,
                "RULE_DDOS_RATE_LIMIT",
                "Rate limit exceeded / burst flood",
                reason
            );
        }
    }

    /**
     * Deep packet inspection across path, query parameters, headers, and payload body.
     */
    public WafEvaluationResult inspect(String clientIp, String method, String path, String queryString,
                                       Map<String, String> headers, String body) {
        String contentType = headerIgnoreCase(headers, "content-type");
        byte[] bodyBytes = body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8);
        List<PayloadSurface> surfaces = payloadNormalizer.normalize(
                path, queryString, headers, bodyBytes, contentType, StandardCharsets.UTF_8);
        return inspectSurfaces(clientIp, method, surfaces);
    }

    /**
     * Inspect every unpacked payload surface with all registered detectors.
     */
    public WafEvaluationResult inspectSurfaces(String clientIp, String method, List<PayloadSurface> surfaces) {
        DdosRateLimiter.RateLimitResult rateResult = ddosRateLimiter.checkRateLimit(clientIp);
        if (!rateResult.allowed()) {
            return WafEvaluationResult.rateLimited(rateResult.reason(), rateResult.isBanned());
        }

        if (surfaces == null) {
            return WafEvaluationResult.clean();
        }

        for (PayloadSurface surface : surfaces) {
            if (surface == null || surface.value() == null || surface.value().isBlank()) {
                continue;
            }
            if (isUserAgentLocation(surface.location()) && isMaliciousScanner(surface.value())) {
                return WafEvaluationResult.blocked(
                        ThreatType.SUSPICIOUS_SCANNER,
                        ThreatSeverity.HIGH,
                        80,
                        "RULE_MALICIOUS_SCANNER_UA",
                        surface.value(),
                        "Malicious vulnerability scanner / automated attack tool detected: " + surface.value()
                );
            }
            WafEvaluationResult result = runDetectorsOnTarget(surface.value(), surface.location());
            if (!result.allowed()) {
                return result;
            }
        }

        return WafEvaluationResult.clean();
    }

    /**
     * Inspect single text payload against all active detectors (useful for simulation testing).
     */
    public WafEvaluationResult inspectPayloadOnly(String payload, ThreatType targetType) {
        if (payload == null || payload.trim().isEmpty()) {
            return WafEvaluationResult.clean();
        }

        for (ThreatDetector detector : detectors) {
            DetectionResult result = detector.detect(payload);
            if (result.detected()) {
                return WafEvaluationResult.blocked(
                    result.threatType(),
                    result.severity(),
                    result.threatScore(),
                    result.ruleName(),
                    result.snippet(),
                    "Detected " + result.threatType() + " payload matching " + result.ruleName()
                );
            }
        }

        return WafEvaluationResult.clean();
    }

    private WafEvaluationResult runDetectorsOnTarget(String content, String location) {
        for (ThreatDetector detector : detectors) {
            DetectionResult result = detector.detect(content);
            if (result.detected()) {
                return WafEvaluationResult.blocked(
                    result.threatType(),
                    result.severity(),
                    result.threatScore(),
                    result.ruleName(),
                    result.snippet(),
                    "Threat detected in " + location + " matching rule [" + result.ruleName() + "]"
                );
            }
        }
        return WafEvaluationResult.clean();
    }

    private boolean isMaliciousScanner(String ua) {
        String lower = ua.toLowerCase(Locale.ROOT);
        return lower.contains("sqlmap") ||
               lower.contains("nikto") ||
               lower.contains("nmap") ||
               lower.contains("dirbuster") ||
               lower.contains("gobuster") ||
               lower.contains("acunetix") ||
               lower.contains("nessus") ||
               lower.contains("w3af") ||
               lower.contains("masscan") ||
               lower.contains("zgrab");
    }

    private static boolean isUserAgentLocation(String location) {
        if (location == null) {
            return false;
        }
        String lower = location.toLowerCase(Locale.ROOT);
        return lower.contains("user-agent");
    }

    private static String headerIgnoreCase(Map<String, String> headers, String name) {
        if (headers == null || name == null) {
            return "";
        }
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(name)) {
                return entry.getValue();
            }
        }
        return "";
    }
}
