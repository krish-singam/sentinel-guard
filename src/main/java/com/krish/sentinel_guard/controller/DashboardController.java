package com.krish.sentinel_guard.controller;

import com.krish.sentinel_guard.model.MonitoredDomain;
import com.krish.sentinel_guard.model.SecurityIncident;
import com.krish.sentinel_guard.repository.BannedIpRepository;
import com.krish.sentinel_guard.repository.MonitoredDomainRepository;
import com.krish.sentinel_guard.repository.SecurityIncidentRepository;
import com.krish.sentinel_guard.service.AlertNotificationService;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;

@RestController
@RequestMapping("/api/dashboard")
public class DashboardController {

    private final SecurityIncidentRepository incidentRepository;
    private final MonitoredDomainRepository domainRepository;
    private final BannedIpRepository bannedIpRepository;
    private final AlertNotificationService alertService;

    public DashboardController(
            SecurityIncidentRepository incidentRepository,
            MonitoredDomainRepository domainRepository,
            BannedIpRepository bannedIpRepository,
            AlertNotificationService alertService) {
        this.incidentRepository = incidentRepository;
        this.domainRepository = domainRepository;
        this.bannedIpRepository = bannedIpRepository;
        this.alertService = alertService;
    }

    public record DashboardStats(
        long totalMonitoredDomains,
        long totalRequestsProcessed,
        long totalBlockedAttacks,
        long totalCleanRequests,
        long activeBannedIps,
        double protectionRatePercentage,
        Map<String, Long> attacksByType,
        List<Map<String, Object>> attacksByCountry,
        List<Map<String, Object>> domainSummary
    ) {}

    @GetMapping("/stats")
    public ResponseEntity<DashboardStats> getDashboardStats() {
        List<MonitoredDomain> domains = domainRepository.findAllByOrderByIdAsc();

        long totalDomains = domains.size();
        long totalRequests = domains.stream().mapToLong(MonitoredDomain::getTotalRequests).sum();
        long totalBlocked = domains.stream().mapToLong(MonitoredDomain::getBlockedRequests).sum();
        long totalClean = domains.stream().mapToLong(MonitoredDomain::getCleanRequests).sum();
        long activeBans = bannedIpRepository.findByActiveTrue().size();

        if (totalRequests == 0) {
            totalBlocked = incidentRepository.countByBlockedTrue();
            totalClean = totalBlocked * 4;
            totalRequests = totalBlocked + totalClean;
        }

        double rate = totalRequests > 0 ? ((double) totalBlocked / totalRequests) * 100.0 : 0.0;

        // Group by Threat Type
        Map<String, Long> attacksByType = new LinkedHashMap<>();
        List<Object[]> typeCounts = incidentRepository.countIncidentsByThreatType();
        for (Object[] row : typeCounts) {
            if (row[0] != null) {
                attacksByType.put(row[0].toString(), ((Number) row[1]).longValue());
            }
        }

        // Group by Country
        List<Map<String, Object>> attacksByCountry = new ArrayList<>();
        List<Object[]> countryCounts = incidentRepository.countIncidentsByCountry(PageRequest.of(0, 8));
        for (Object[] row : countryCounts) {
            if (row[0] != null) {
                attacksByCountry.add(Map.of(
                    "country", row[0].toString(),
                    "count", ((Number) row[1]).longValue()
                ));
            }
        }

        // Domain Summary List
        List<Map<String, Object>> domainSummary = domains.stream().map(d -> {
            Map<String, Object> map = new HashMap<>();
            map.put("id", d.getId());
            map.put("domainName", d.getDomainName());
            map.put("displayName", d.getDisplayName());
            map.put("primaryIp", d.getPrimaryIp());
            map.put("country", d.getCountry());
            map.put("sslStatus", d.getSslStatus());
            map.put("sslDaysRemaining", d.getSslDaysRemaining());
            map.put("healthStatus", d.getHealthStatus());
            map.put("totalRequests", d.getTotalRequests());
            map.put("blockedRequests", d.getBlockedRequests());
            map.put("isProtected", d.getIsProtected());
            return map;
        }).toList();

        return ResponseEntity.ok(new DashboardStats(
            totalDomains,
            totalRequests,
            totalBlocked,
            totalClean,
            activeBans,
            Math.round(rate * 10.0) / 10.0,
            attacksByType,
            attacksByCountry,
            domainSummary
        ));
    }

    @GetMapping("/live-feed")
    public ResponseEntity<List<SecurityIncident>> getLiveIncidents(
            @org.springframework.web.bind.annotation.RequestParam(required = false) String domain,
            @org.springframework.web.bind.annotation.RequestParam(required = false) com.krish.sentinel_guard.model.ThreatType threatType,
            @org.springframework.web.bind.annotation.RequestParam(required = false) String timeRange,
            @org.springframework.web.bind.annotation.RequestParam(required = false) Integer limit) {
        int maxLimit = (limit != null && limit > 0 && limit <= 500) ? limit : 100;

        java.time.LocalDateTime since = null;
        if (timeRange != null && !timeRange.equalsIgnoreCase("all")) {
            switch (timeRange.toLowerCase()) {
                case "24h" -> since = java.time.LocalDateTime.now().minusHours(24);
                case "7d" -> since = java.time.LocalDateTime.now().minusDays(7);
                case "30d" -> since = java.time.LocalDateTime.now().minusDays(30);
                case "90d" -> since = java.time.LocalDateTime.now().minusDays(90);
                case "180d", "6m" -> since = java.time.LocalDateTime.now().minusDays(180);
                default -> {}
            }
        }

        if (since != null) {
            return ResponseEntity.ok(incidentRepository.findByTimestampAfterOrderByTimestampDesc(since, PageRequest.of(0, maxLimit)));
        }

        if (domain != null && !domain.trim().isEmpty()) {
            return ResponseEntity.ok(incidentRepository.findByDomainNameIgnoreCaseOrderByTimestampDesc(domain.trim(), PageRequest.of(0, maxLimit)));
        }
        if (threatType != null) {
            return ResponseEntity.ok(incidentRepository.findByThreatTypeOrderByTimestampDesc(threatType, PageRequest.of(0, maxLimit)));
        }
        return ResponseEntity.ok(incidentRepository.findByOrderByTimestampDesc(PageRequest.of(0, maxLimit)));
    }

    @GetMapping("/alerts")
    public ResponseEntity<List<AlertNotificationService.DispatchedAlert>> getRecentAlerts() {
        return ResponseEntity.ok(alertService.getRecentAlerts());
    }
}
