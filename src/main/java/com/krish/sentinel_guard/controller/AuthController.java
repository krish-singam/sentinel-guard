package com.krish.sentinel_guard.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    public record UserProfileDto(
        String username,
        String fullName,
        String email,
        String role,
        List<String> authorities,
        boolean isSuperAdmin,
        boolean canSimulateAttacks,
        boolean canManageDomains
    ) {}

    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getSystemStatus() {
        return ResponseEntity.ok(Map.of(
            "status", "UP",
            "service", "SentinelGuard WAF & Threat Intelligence Engine",
            "version", "1.0.0",
            "timestamp", LocalDateTime.now().toString(),
            "virtualThreadsActive", true
        ));
    }

    @PostMapping("/login")
    public ResponseEntity<UserProfileDto> login(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).build();
        }
        return getCurrentUser(authentication);
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            new SecurityContextLogoutHandler().logout(request, response, auth);
        }
        return ResponseEntity.ok(Map.of("message", "Logged out successfully", "status", "LOGGED_OUT"));
    }

    @GetMapping("/me")
    public ResponseEntity<UserProfileDto> getCurrentUser(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).build();
        }

        String username = authentication.getName();
        List<String> authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        boolean isSuperAdmin = authorities.contains("ROLE_SUPER_ADMIN");
        boolean isAnalyst = authorities.contains("ROLE_SECURITY_ANALYST");

        String fullName = switch (username) {
            case "krishna" -> "Krishna Singamsetti (Lead Security Architect)";
            case "alex" -> "Alex Mercer (Security Operations Analyst)";
            case "sarah" -> "Sarah Connor (Compliance & Security Auditor)";
            default -> username;
        };

        String email = username + "@singamsettikrishna.in";
        String primaryRole = isSuperAdmin ? "ROLE_SUPER_ADMIN" : (isAnalyst ? "ROLE_SECURITY_ANALYST" : "ROLE_AUDITOR");

        return ResponseEntity.ok(new UserProfileDto(
            username,
            fullName,
            email,
            primaryRole,
            authorities,
            isSuperAdmin,
            isSuperAdmin, // only super admin can simulate
            isSuperAdmin || isAnalyst
        ));
    }

    @GetMapping("/roles")
    public ResponseEntity<List<Map<String, String>>> getAvailableDemoRoles() {
        return ResponseEntity.ok(List.of(
            Map.of("username", "krishna", "role", "SUPER_ADMIN", "label", "Krishna (Super Administrator)", "access", "Full Access + Red-Team Attack Simulation Sandbox"),
            Map.of("username", "alex", "role", "SECURITY_ANALYST", "label", "Alex (Security Analyst)", "access", "Domain Intelligence, Firewall & Alerts (Simulator Locked)"),
            Map.of("username", "sarah", "role", "AUDITOR", "label", "Sarah (Compliance Auditor)", "access", "Read-Only Reports & Incident Feeds")
        ));
    }
}
