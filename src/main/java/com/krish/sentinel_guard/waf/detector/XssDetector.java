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
public class XssDetector implements ThreatDetector {

    private record Rule(String name, Pattern pattern, ThreatSeverity severity, int score) {}

    private final List<Rule> rules = List.of(
        // Direct script tags
        new Rule("XSS_SCRIPT_TAG",
            Pattern.compile("(?i)<\\s*script[^>]*>.*?<\\s*/\\s*script\\s*>", Pattern.DOTALL),
            ThreatSeverity.CRITICAL, 95),

        new Rule("XSS_OPEN_SCRIPT_TAG",
            Pattern.compile("(?i)<\\s*script[^>]*>", Pattern.CASE_INSENSITIVE),
            ThreatSeverity.CRITICAL, 90),

        // JavaScript & VBScript URI schemes
        new Rule("XSS_JAVASCRIPT_URI",
            Pattern.compile("(?i)(javascript|vbscript|data\\s*:\\s*text/html)\\s*:", Pattern.CASE_INSENSITIVE),
            ThreatSeverity.HIGH, 90),

        // Event handler attributes (onload, onerror, onclick, etc.)
        new Rule("XSS_DOM_EVENT_HANDLER",
            Pattern.compile("(?i)\\b(on(error|load|click|mouseover|mouseenter|focus|blur|submit|change|keydown|keyup|keypress|drag|drop|pointerdown|wheel|touchstart))\\s*=\\s*['\"]?[^'\">]+", Pattern.CASE_INSENSITIVE),
            ThreatSeverity.HIGH, 90),

        // SVG onload / execution vectors
        new Rule("XSS_SVG_VECTOR",
            Pattern.compile("(?i)<\\s*svg[^>]*on\\w+\\s*=|(?i)<\\s*svg/onload\\s*=", Pattern.CASE_INSENSITIVE),
            ThreatSeverity.HIGH, 90),

        // Dangerous embed / iframe / object / base tags
        new Rule("XSS_DANGEROUS_ELEMENT",
            Pattern.compile("(?i)<\\s*(iframe|object|embed|applet|meta|base|link)\\b[^>]*>", Pattern.CASE_INSENSITIVE),
            ThreatSeverity.HIGH, 85),

        // Cookie stealing & DOM manipulation payloads
        new Rule("XSS_COOKIE_THEFT_OR_EVAL",
            Pattern.compile("(?i)(document\\.cookie|window\\.location|eval\\s*\\(|alert\\s*\\(|prompt\\s*\\(|confirm\\s*\\(|String\\.fromCharCode\\s*\\()", Pattern.CASE_INSENSITIVE),
            ThreatSeverity.HIGH, 85)
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
                    ThreatType.XSS,
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
        return "Cross-Site Scripting (XSS) Sanitizer Engine";
    }
}
