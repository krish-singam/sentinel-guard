package com.krish.sentinel_guard.waf.detector;

import com.krish.sentinel_guard.model.ThreatSeverity;
import com.krish.sentinel_guard.model.ThreatType;
import org.springframework.stereotype.Component;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class SsrfDetector implements ThreatDetector {

    private static final List<RulePattern> SSRF_PATTERNS = List.of(
        // AWS / Cloud IMDS metadata endpoint
        new RulePattern(
            Pattern.compile("169\\.254\\.169\\.254|metadata\\.google\\.internal|100\\.100\\.100\\.200|latest/meta-data|latest/api/token", Pattern.CASE_INSENSITIVE),
            "SSRF_CLOUD_METADATA_EXFILTRATION",
            ThreatSeverity.CRITICAL,
            100
        ),
        // Localhost / Loopback / Hex / Decimal IP evasion
        new RulePattern(
            Pattern.compile("(?:https?|ftp|gopher|dict|file|ldap|tftp)://(?:127\\.0\\.0\\.1|localhost|0\\.0\\.0\\.0|127\\.0|127\\.1|0x7f000001|2130706433|\\[::1\\]|::1)", Pattern.CASE_INSENSITIVE),
            "SSRF_LOCALHOST_LOOPBACK",
            ThreatSeverity.CRITICAL,
            95
        ),
        // Dangerous non-HTTP protocols in parameters
        new RulePattern(
            Pattern.compile("(?:file|gopher|dict|tftp|netdoc|jar|expect|php)://", Pattern.CASE_INSENSITIVE),
            "SSRF_DANGEROUS_URI_SCHEME",
            ThreatSeverity.CRITICAL,
            95
        ),
        // Private Internal RFC1918 IPv4 ranges in query params
        new RulePattern(
            Pattern.compile("(?:https?://)?(?:10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3}|172\\.(?:1[6-9]|2\\d|3[0-1])\\.\\d{1,3}\\.\\d{1,3})(?::\\d+)?(?:/|$)", Pattern.CASE_INSENSITIVE),
            "SSRF_INTERNAL_RFC1918_NETWORK_PROBE",
            ThreatSeverity.HIGH,
            90
        )
    );

    @Override
    public DetectionResult detect(String input) {
        if (input == null || input.isBlank()) {
            return DetectionResult.clean();
        }

        String decoded = safeUrlDecode(input);

        for (RulePattern rule : SSRF_PATTERNS) {
            Matcher m1 = rule.pattern.matcher(input);
            if (m1.find()) {
                return DetectionResult.detected(ThreatType.SSRF, rule.severity, rule.score, rule.ruleName, rule.pattern.pattern(), m1.group());
            }

            Matcher m2 = rule.pattern.matcher(decoded);
            if (m2.find()) {
                return DetectionResult.detected(ThreatType.SSRF, rule.severity, rule.score, rule.ruleName, rule.pattern.pattern(), m2.group());
            }
        }

        return DetectionResult.clean();
    }

    @Override
    public String getDetectorName() {
        return "SSRF & Cloud Metadata Protection Detector";
    }

    private String safeUrlDecode(String val) {
        try {
            return URLDecoder.decode(val, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return val;
        }
    }

    private record RulePattern(Pattern pattern, String ruleName, ThreatSeverity severity, int score) {}
}
