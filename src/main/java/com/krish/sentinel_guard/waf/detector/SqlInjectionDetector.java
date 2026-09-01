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
public class SqlInjectionDetector implements ThreatDetector {

    private record Rule(String name, Pattern pattern, ThreatSeverity severity, int score) {}

    private final List<Rule> rules = List.of(
        // Classic Tautologies
        new Rule("SQLI_TAUTOLOGY_OR",
            Pattern.compile("(?i)(\\b(or|and)\\b\\s+['\"\\d]+\\s*=\\s*['\"\\d]+|\\b(or|and)\\b\\s+true\\b|\\b(or|and)\\b\\s+'[^']*'\\s*=\\s*'[^']*')", Pattern.CASE_INSENSITIVE),
            ThreatSeverity.HIGH, 85),

        new Rule("SQLI_ADMIN_BYPASS",
            Pattern.compile("(?i)(\\badmin'\\s*--|'\\s*or\\s*1\\s*=\\s*1\\s*--|'\\s*or\\s*'1'\\s*=\\s*'1')", Pattern.CASE_INSENSITIVE),
            ThreatSeverity.CRITICAL, 95),

        // UNION SELECT queries
        new Rule("SQLI_UNION_SELECT",
            Pattern.compile("(?i)\\bunion(\\s+all)?\\s+select\\b", Pattern.CASE_INSENSITIVE),
            ThreatSeverity.CRITICAL, 95),

        // Stacked Query & Destructive DDL / DML
        new Rule("SQLI_STACKED_DDL",
            Pattern.compile("(?i);\\s*(drop\\s+table|delete\\s+from|alter\\s+table|truncate\\s+table|insert\\s+into|update\\s+\\w+\\s+set|exec(\\s+xp_cmdshell|ute)?)\\b", Pattern.CASE_INSENSITIVE),
            ThreatSeverity.CRITICAL, 100),

        // Time-based blind injection
        new Rule("SQLI_TIME_BLIND",
            Pattern.compile("(?i)(\\bwaitfor\\s+delay\\b|\\bpg_sleep\\s*\\(|\\bsleep\\s*\\(\\s*\\d+\\s*\\)|\\bbenchmark\\s*\\(\\s*\\d+)", Pattern.CASE_INSENSITIVE),
            ThreatSeverity.HIGH, 90),

        // Information schema & database metadata extraction
        new Rule("SQLI_INFO_SCHEMA",
            Pattern.compile("(?i)\\b(information_schema|sysdatabases|sysobjects|all_tables|table_name|column_name)\\b", Pattern.CASE_INSENSITIVE),
            ThreatSeverity.HIGH, 80),

        // Out-of-band & XML error based
        new Rule("SQLI_ERROR_BASED",
            Pattern.compile("(?i)(\\bextractvalue\\s*\\(|\\bupdatexml\\s*\\(|\\bload_file\\s*\\(|\\binto\\s+(out|dump)file\\b)", Pattern.CASE_INSENSITIVE),
            ThreatSeverity.HIGH, 85),

        // Inline comment delimiters used for SQL evasion
        new Rule("SQLI_COMMENT_EVASION",
            Pattern.compile("(/\\*!\\d+.*?\\*/|/\\*\\*/.*\\b(select|union|insert|delete)\\b)", Pattern.CASE_INSENSITIVE),
            ThreatSeverity.MEDIUM, 75)
    );

    @Override
    public DetectionResult detect(String rawInput) {
        if (rawInput == null || rawInput.trim().isEmpty()) {
            return DetectionResult.clean();
        }

        String decodedInput = safeDecode(rawInput);
        String normalizedInput = decodedInput.replaceAll("\\s+", " ");

        for (Rule rule : rules) {
            Matcher matcher = rule.pattern().matcher(normalizedInput);
            if (matcher.find()) {
                String matchedText = matcher.group();
                String snippet = extractSnippet(normalizedInput, matcher.start(), matcher.end());
                return DetectionResult.detected(
                    ThreatType.SQL_INJECTION,
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
        return "SQL Injection Deep Packet Inspector";
    }
}
