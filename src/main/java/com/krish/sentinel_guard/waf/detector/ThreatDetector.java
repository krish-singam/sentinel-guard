package com.krish.sentinel_guard.waf.detector;

public interface ThreatDetector {
    DetectionResult detect(String input);
    String getDetectorName();
}
