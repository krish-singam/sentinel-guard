package com.krish.sentinel_guard.waf.detector;

import com.krish.sentinel_guard.model.ThreatSeverity;
import com.krish.sentinel_guard.model.ThreatType;

public record DetectionResult(
    boolean detected,
    ThreatType threatType,
    ThreatSeverity severity,
    int threatScore,
    String ruleName,
    String matchedPattern,
    String snippet
) {
    public static DetectionResult clean() {
        return new DetectionResult(false, ThreatType.CLEAN, ThreatSeverity.INFO, 0, "CLEAN_TRAFFIC", null, null);
    }

    public static DetectionResult detected(ThreatType type, ThreatSeverity severity, int score, String ruleName, String pattern, String snippet) {
        return new DetectionResult(true, type, severity, score, ruleName, pattern, snippet);
    }
}
