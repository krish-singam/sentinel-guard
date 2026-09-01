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
public class CrlfInjectionDetector implements ThreatDetector {

    private static final List<RulePattern> PATTERNS = List.of(
        new RulePattern(
            Pattern.compile("(?:%0d%0a|%0d|%0a|\\r\\n|\\r|\\n)\\s*(?:Set-Cookie|Location|Content-Type|X-XSS-Protection):", Pattern.CASE_INSENSITIVE),
            "CRLF_HTTP_RESPONSE_SPLITTING",
            ThreatType.CRLF_INJECTION,
            ThreatSeverity.HIGH,
            90
        ),
        new RulePattern(
            Pattern.compile("(?:%0d%0a|%0d|%0a|\\r\\n|\\r|\\n)\\s*<script>", Pattern.CASE_INSENSITIVE),
            "CRLF_XSS_INJECTION",
            ThreatType.CRLF_INJECTION,
            ThreatSeverity.HIGH,
            95
        )
    );

    @Override
    public DetectionResult detect(String input) {
        if (input == null || input.isBlank()) {
            return DetectionResult.clean();
        }

        String decoded = safeUrlDecode(input);

        for (RulePattern rule : PATTERNS) {
            Matcher m1 = rule.pattern.matcher(input);
            if (m1.find()) {
                return DetectionResult.detected(rule.threatType, rule.severity, rule.score, rule.ruleName, rule.pattern.pattern(), m1.group());
            }

            Matcher m2 = rule.pattern.matcher(decoded);
            if (m2.find()) {
                return DetectionResult.detected(rule.threatType, rule.severity, rule.score, rule.ruleName, rule.pattern.pattern(), m2.group());
            }
        }

        return DetectionResult.clean();
    }

    @Override
    public String getDetectorName() {
        return "CRLF & HTTP Header Injection Detector";
    }

    private String safeUrlDecode(String val) {
        try {
            return URLDecoder.decode(val, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return val;
        }
    }

    private record RulePattern(Pattern pattern, String ruleName, ThreatType threatType, ThreatSeverity severity, int score) {}
}
