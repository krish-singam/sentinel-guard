package com.krish.sentinel_guard.controller;

import com.krish.sentinel_guard.model.BannedIp;
import com.krish.sentinel_guard.model.ThreatType;
import com.krish.sentinel_guard.waf.detector.DdosRateLimiter;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/firewall")
@PreAuthorize("hasAnyRole('SUPER_ADMIN', 'SECURITY_ANALYST')")
public class FirewallController {

    private final DdosRateLimiter ddosRateLimiter;

    public FirewallController(DdosRateLimiter ddosRateLimiter) {
        this.ddosRateLimiter = ddosRateLimiter;
    }

    public record BanIpRequest(
        @NotBlank(message = "IP address is required") String ipAddress,
        String reason,
        int durationSeconds
    ) {}

    @GetMapping("/banned-ips")
    public ResponseEntity<List<BannedIp>> getBannedIps() {
        return ResponseEntity.ok(ddosRateLimiter.getActiveBannedIps());
    }

    @PostMapping("/ban")
    public ResponseEntity<Map<String, Object>> manualBanIp(@Valid @RequestBody BanIpRequest request) {
        int duration = request.durationSeconds() > 0 ? request.durationSeconds() : 600;
        String reason = request.reason() != null && !request.reason().isBlank() ? request.reason() : "Manual Security Administrator Jail Ban";

        ddosRateLimiter.banIp(request.ipAddress(), reason, ThreatType.SUSPICIOUS_SCANNER, duration);
        return ResponseEntity.ok(Map.of("message", "IP " + request.ipAddress() + " jailed for " + duration + " seconds.", "success", true));
    }

    @PostMapping("/unban")
    public ResponseEntity<Map<String, Object>> unbanIp(@RequestParam String ipAddress) {
        boolean unbanned = ddosRateLimiter.unbanIp(ipAddress);
        return ResponseEntity.ok(Map.of("message", unbanned ? "IP " + ipAddress + " released from firewall jail." : "IP not found or already inactive.", "success", unbanned));
    }
}
