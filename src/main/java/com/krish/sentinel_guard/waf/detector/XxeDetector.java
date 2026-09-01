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
public class XxeDetector implements ThreatDetector {

    private static final List<RulePattern> XXE_PATTERNS = List.of(
        new RulePattern(
            Pattern.compile("<!ENTITY\\s+[^>]+(?:SYSTEM|PUBLIC)\\s+[\"'][^\"']+[\"']", Pattern.CASE_INSENSITIVE),
            "XXE_EXTERNAL_ENTITY_DECLARATION",
            ThreatSeverity.CRITICAL,
            100
        ),
        new RulePattern(
            Pattern.compile("<!DOCTYPE\\s+[^>\\[]*\\[[^\\]]*<!ENTITY", Pattern.CASE_INSENSITIVE | Pattern.DOTALL),
            "XXE_DOCTYPE_INLINE_DTD_INJECTION",
            ThreatSeverity.CRITICAL,
            95
        ),
        new RulePattern(
            Pattern.compile("xmlns:xi\\s*=\\s*[\"']http://www\\.w3\\.org/2001/XInclude[\"']|<xi:include", Pattern.CASE_INSENSITIVE),
            "XXE_XINCLUDE_ATTACK",
            ThreatSeverity.HIGH,
            90
        ),
        new RulePattern(
            Pattern.compile("SYSTEM\\s+[\"'](?:file|http|https|ftp|expect|php|gopher)://", Pattern.CASE_INSENSITIVE),
            "XXE_SYSTEM_URI_RESOLVER",
            ThreatSeverity.CRITICAL,
            95
        )
    );

    @Override
    public DetectionResult detect(String input) {
        if (input == null || input.isBlank()) {
            return DetectionResult.clean();
        }

        String decoded = safeUrlDecode(input);

        for (RulePattern rule : XXE_PATTERNS) {
            Matcher m1 = rule.pattern.matcher(input);
            if (m1.find()) {
                return DetectionResult.detected(ThreatType.XXE, rule.severity, rule.score, rule.ruleName, rule.pattern.pattern(), m1.group());
            }

            Matcher m2 = rule.pattern.matcher(decoded);
            if (m2.find()) {
                return DetectionResult.detected(ThreatType.XXE, rule.severity, rule.score, rule.ruleName, rule.pattern.pattern(), m2.group());
            }
        }

        return DetectionResult.clean();
    }

    @Override
    public String getDetectorName() {
        return "XML External Entity (XXE) Injection Detector";
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
