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
public class RceDetector implements ThreatDetector {

    private record Rule(String name, Pattern pattern, ThreatSeverity severity, int score) {}

    private final List<Rule> rules = List.of(
        // Shell command chaining and pipes
        new Rule("RCE_SHELL_PIPES",
            Pattern.compile("(?i)[;&|`$]\\s*(/bin/(ba)?sh|/usr/bin/python|cmd(\\.exe)?|powershell(\\.exe)?|sh|bash)\\b"),
            ThreatSeverity.CRITICAL, 100),

        // System reconnaissance commands
        new Rule("RCE_SYSTEM_RECON",
            Pattern.compile("(?i)(cat\\s+/etc/(passwd|shadow|hosts|issue)|/bin/cat|whoami|\\bid\\b|uname\\s+-a|netstat\\s+-[a-z]+|ipconfig|ifconfig|hostname)"),
            ThreatSeverity.CRITICAL, 95),

        // Command substitution
        new Rule("RCE_COMMAND_SUBSTITUTION",
            Pattern.compile("(\\$\\([a-zA-Z0-9_/\\s-]+\\)|`[a-zA-Z0-9_/\\s-]+`)"),
            ThreatSeverity.CRITICAL, 95),

        // Remote payload download & execution
        new Rule("RCE_DOWNLOAD_EXEC",
            Pattern.compile("(?i)(curl|wget)\\s+https?://[^\\s|&;]+?\\s*\\|\\s*(sh|bash|python|perl|php)"),
            ThreatSeverity.CRITICAL, 100),

        // Reverse shells (nc, ncat, bash -i)
        new Rule("RCE_REVERSE_SHELL",
            Pattern.compile("(?i)(nc|ncat|netcat)\\s+-[ecl]\\s+|bash\\s+-i\\s+>&\\s+/dev/tcp/"),
            ThreatSeverity.CRITICAL, 100),

        // Log4j / JNDI Injection
        new Rule("RCE_LOG4J_JNDI",
            Pattern.compile("(?i)\\$\\{(lower:|upper:)?jndi:(ldap|rmi|dns|nis|iiop)://"),
            ThreatSeverity.CRITICAL, 100),

        // Java / Spring Expression Language (SpEL) injection
        new Rule("RCE_JAVA_SPEL",
            Pattern.compile("(?i)(T\\s*\\(\\s*java\\.lang\\.Runtime\\s*\\)|getRuntime\\s*\\(\\s*\\)\\.exec\\b|ProcessBuilder\\s*\\()"),
            ThreatSeverity.CRITICAL, 100)
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
                    ThreatType.REMOTE_CODE_EXECUTION,
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
        return "Remote Code Execution (RCE) Defense Engine";
    }
}
