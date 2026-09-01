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
public class PathTraversalDetector implements ThreatDetector {

    private record Rule(String name, Pattern pattern, ThreatSeverity severity, int score) {}

    private final List<Rule> rules = List.of(
        // Direct dot-dot-slash traversal
        new Rule("PATH_TRAVERSAL_DOT_DOT",
            Pattern.compile("(\\.\\.[\\\\/]|\\.[\\\\/]\\.\\.)"),
            ThreatSeverity.HIGH, 85),

        // Encoded dot-dot-slash (%2e%2e%2f)
        new Rule("PATH_TRAVERSAL_ENCODED",
            Pattern.compile("(?i)(%2e%2e%2f|%2e%2e/|\\.\\.%2f|%252e%252e%252f)"),
            ThreatSeverity.HIGH, 90),

        // Null byte injection
        new Rule("PATH_NULL_BYTE",
            Pattern.compile("(%00|\\x00|\\\\0)"),
            ThreatSeverity.HIGH, 85),

        // Sensitive config & system file targets
        new Rule("PATH_SENSITIVE_FILES",
            Pattern.compile("(?i)(/etc/(passwd|shadow|hosts)|(winnt|windows)/system32|web\\.xml|application\\.properties|application\\.yml|\\.env\\b|\\.git/)"),
            ThreatSeverity.CRITICAL, 95)
    );

    @Override
    public DetectionResult detect(String rawInput) {
        if (rawInput == null || rawInput.trim().isEmpty()) {
            return DetectionResult.clean();
        }

        String decodedInput = safeDecode(rawInput);

        for (Rule rule : rules) {
            Matcher matcher = rule.pattern().matcher(decodedInput);
            if (matcher.find()) {
                String matchedText = matcher.group();
                String snippet = extractSnippet(decodedInput, matcher.start(), matcher.end());
                return DetectionResult.detected(
                    ThreatType.PATH_TRAVERSAL,
                    rule.severity(),
                    rule.score(),
                    rule.name(),
                    matchedText,
                    snippet
                );
            }
        }

        return DetectionResult.clean();
    }

    private String safeDecode(String input) {
        try {
            return URLDecoder.decode(input, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return input;
        }
    }

    private String extractSnippet(String full, int start, int end) {
        int s = Math.max(0, start - 20);
        int e = Math.min(full.length(), end + 20);
        return full.substring(s, e);
    }

    @Override
    public String getDetectorName() {
        return "Path Traversal & Local File Inclusion Inspector";
    }
}
