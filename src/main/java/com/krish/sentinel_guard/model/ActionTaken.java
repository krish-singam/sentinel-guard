package com.krish.sentinel_guard.model;

public enum ActionTaken {
    PASSED_CLEAN,
    BLOCKED_403,
    RATE_LIMITED_429,
    IP_BANNED,
    LOGGED_ALERT
}
