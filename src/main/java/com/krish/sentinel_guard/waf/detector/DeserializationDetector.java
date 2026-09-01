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
public class DeserializationDetector implements ThreatDetector {

    private static final List<RulePattern> PATTERNS = List.of(
        // Java Object Deserialization Magic Bytes (rO0AB / aced0005) or ysoserial gadgets
        new RulePattern(
            Pattern.compile("rO0AB[A-Za-z0-9+/]{10,}|aced0005|org\\.apache\\.commons\\.collections(?:4)?\\.functors|com\\.sun\\.rowset\\.JdbcRowSetImpl", Pattern.CASE_INSENSITIVE),
            "DESERIALIZATION_JAVA_MAGIC_BYTES_GADGET",
            ThreatType.DESERIALIZATION_ATTACK,
            ThreatSeverity.CRITICAL,
            100
        ),
        // Fastjson / Jackson Polymorphic Deserialization Exploit
        new RulePattern(
            Pattern.compile("\"@type\"\\s*:\\s*\"(?:com\\.sun\\.rowset\\.JdbcRowSetImpl|ch\\.qos\\.logback|org\\.apache\\.xbean|org\\.springframework)", Pattern.CASE_INSENSITIVE),
            "DESERIALIZATION_POLYMORPHIC_JSON_AUTO_TYPE",
            ThreatType.DESERIALIZATION_ATTACK,
            ThreatSeverity.CRITICAL,
            100
        ),
        // Prototype Pollution
        new RulePattern(
            Pattern.compile("__proto__|\"__proto__\"|constructor\\.prototype|Object\\.prototype", Pattern.CASE_INSENSITIVE),
            "PROTOTYPE_POLLUTION_MUTATION",
            ThreatType.PROTOTYPE_POLLUTION,
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
        return "Insecure Deserialization & Prototype Pollution Detector";
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
