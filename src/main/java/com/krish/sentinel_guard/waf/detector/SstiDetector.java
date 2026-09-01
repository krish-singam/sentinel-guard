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
public class SstiDetector implements ThreatDetector {

    private static final List<RulePattern> SSTI_PATTERNS = List.of(
        // Jinja2 / Twig / Python template evaluation
        new RulePattern(
            Pattern.compile("\\{\\{.*(?:__class__|__mro__|__subclasses__|__globals__|__builtins__|config\\.items|request\\.application|lipsum|cycler).*\\}\\}", Pattern.CASE_INSENSITIVE),
            "SSTI_JINJA2_PYTHON_EXPLOITATION",
            ThreatSeverity.CRITICAL,
            100
        ),
        // Generic template math probe: {{7*7}}, ${7*7}, #{7*7}
        new RulePattern(
            Pattern.compile("(?:\\{\\{|\\$\\{|#\\{)\\s*\\d+\\s*[*+\\-/]\\s*\\d+\\s*(?:\\}\\}|\\})", Pattern.CASE_INSENSITIVE),
            "SSTI_TEMPLATE_PROBE_EXPRESSION",
            ThreatSeverity.HIGH,
            85
        ),
        // FreeMarker / Velocity template payload
        new RulePattern(
            Pattern.compile("<#(?:assign|exec|include|import)|\\$\\{\\s*\"?freemarker\\.template\\.utility\\.Execute\"?", Pattern.CASE_INSENSITIVE),
            "SSTI_FREEMARKER_EXEC_EXPLOIT",
            ThreatSeverity.CRITICAL,
            100
        ),
        // Spring SpEL / Thymeleaf template injection
        new RulePattern(
            Pattern.compile("(?:__\\$\\{|\\$\\{\\s*T\\(|#\\{\\s*T\\()\\s*java\\.lang\\.(?:Runtime|ProcessBuilder)", Pattern.CASE_INSENSITIVE),
            "SSTI_SPEL_RUNTIME_EXECUTION",
            ThreatSeverity.CRITICAL,
            100
        )
    );

    @Override
    public DetectionResult detect(String input) {
        if (input == null || input.isBlank()) {
            return DetectionResult.clean();
        }

        String decoded = safeUrlDecode(input);

        for (RulePattern rule : SSTI_PATTERNS) {
            Matcher m1 = rule.pattern.matcher(input);
            if (m1.find()) {
                return DetectionResult.detected(ThreatType.SSTI, rule.severity, rule.score, rule.ruleName, rule.pattern.pattern(), m1.group());
            }

            Matcher m2 = rule.pattern.matcher(decoded);
            if (m2.find()) {
                return DetectionResult.detected(ThreatType.SSTI, rule.severity, rule.score, rule.ruleName, rule.pattern.pattern(), m2.group());
            }
        }

        return DetectionResult.clean();
    }

    @Override
    public String getDetectorName() {
        return "Server-Side Template Injection (SSTI) Detector";
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
