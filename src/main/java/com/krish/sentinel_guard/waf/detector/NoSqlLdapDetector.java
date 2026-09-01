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
public class NoSqlLdapDetector implements ThreatDetector {

    private static final List<RulePattern> PATTERNS = List.of(
        // MongoDB Operator Injections ($gt, $ne, $where, $regex)
        new RulePattern(
            Pattern.compile("(?:\\[\\$ne\\]|\\[\\$gt\\]|\\[\\$gte\\]|\\[\\$regex\\]|\\[\\$where\\]|\\[\\$exists\\]|\\[\\$in\\]|\\[\\$nin\\])", Pattern.CASE_INSENSITIVE),
            "NOSQL_PARAM_ARRAY_OPERATOR_INJECTION",
            ThreatType.NOSQL_INJECTION,
            ThreatSeverity.HIGH,
            90
        ),
        new RulePattern(
            Pattern.compile("(?:\".*\"\\s*:\\s*\\{\\s*\"\\$(?:gt|gte|ne|in|nin|regex|where|exists)\"\\s*:\\s*)", Pattern.CASE_INSENSITIVE),
            "NOSQL_JSON_QUERY_BYPASS",
            ThreatType.NOSQL_INJECTION,
            ThreatSeverity.HIGH,
            95
        ),
        new RulePattern(
            Pattern.compile("\\$where\\s*:\\s*[\"']?function\\s*\\(", Pattern.CASE_INSENSITIVE),
            "NOSQL_WHERE_JS_EXECUTION",
            ThreatType.NOSQL_INJECTION,
            ThreatSeverity.CRITICAL,
            100
        ),
        // LDAP Filter Injection
        new RulePattern(
            Pattern.compile("\\*\\)\\s*\\(\\s*\\|\\s*\\(|\\)\\s*\\(\\s*&\\s*\\(|admin\\*\\)\\s*\\(|\\*\\)\\s*\\(objectClass=\\*", Pattern.CASE_INSENSITIVE),
            "LDAP_FILTER_OR_AND_BYPASS",
            ThreatType.LDAP_INJECTION,
            ThreatSeverity.HIGH,
            90
        ),
        new RulePattern(
            Pattern.compile("\\([a-zA-Z0-9_-]+=\\*\\)\\([a-zA-Z0-9_-]+=", Pattern.CASE_INSENSITIVE),
            "LDAP_WILDCARD_ENUMERATION",
            ThreatType.LDAP_INJECTION,
            ThreatSeverity.MEDIUM,
            80
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
        return "NoSQL & LDAP Injection Detector";
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
