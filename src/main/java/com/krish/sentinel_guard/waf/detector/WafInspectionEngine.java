package com.krish.sentinel_guard.waf.detector;

import com.krish.sentinel_guard.model.ActionTaken;
import com.krish.sentinel_guard.model.ThreatSeverity;
import com.krish.sentinel_guard.model.ThreatType;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
public class WafInspectionEngine {

    private final List<ThreatDetector> detectors;
    private final DdosRateLimiter ddosRateLimiter;

    public WafInspectionEngine(
            List<ThreatDetector> detectors,
            DdosRateLimiter ddosRateLimiter) {
        this.detectors = detectors;
        this.ddosRateLimiter = ddosRateLimiter;
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

        // 1. Rate Limit & DDoS check first
        DdosRateLimiter.RateLimitResult rateResult = ddosRateLimiter.checkRateLimit(clientIp);
        if (!rateResult.allowed()) {
            return WafEvaluationResult.rateLimited(rateResult.reason(), rateResult.isBanned());
        }

        // 2. Inspect Request Path
        if (path != null) {
            WafEvaluationResult pathResult = runDetectorsOnTarget(path, "URI Path");
            if (!pathResult.allowed()) return pathResult;
        }

        // 3. Inspect Query String
        if (queryString != null && !queryString.trim().isEmpty()) {
            WafEvaluationResult queryResult = runDetectorsOnTarget(queryString, "Query String");
            if (!queryResult.allowed()) return queryResult;
        }

        // 4. Inspect Dangerous Headers (User-Agent, Referer, Cookie, etc.)
        if (headers != null) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                String headerName = entry.getKey().toLowerCase();
                String headerVal = entry.getValue();

                if (headerVal == null) continue;

                // Check malicious scanners / tool user-agents
                if (headerName.equals("user-agent")) {
                    if (isMaliciousScanner(headerVal)) {
                        return WafEvaluationResult.blocked(
                            ThreatType.SUSPICIOUS_SCANNER,
                            ThreatSeverity.HIGH,
                            80,
                            "RULE_MALICIOUS_SCANNER_UA",
                            headerVal,
                            "Malicious vulnerability scanner / automated attack tool detected: " + headerVal
                        );
                    }
                }

                WafEvaluationResult headerResult = runDetectorsOnTarget(headerVal, "HTTP Header [" + headerName + "]");
                if (!headerResult.allowed()) return headerResult;
            }
        }

        // 5. Inspect Request Body
        if (body != null && !body.trim().isEmpty()) {
            WafEvaluationResult bodyResult = runDetectorsOnTarget(body, "HTTP Request Body");
            if (!bodyResult.allowed()) return bodyResult;
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
        String lower = ua.toLowerCase();
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
}
