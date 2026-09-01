package com.krish.sentinel_guard.service;

import com.krish.sentinel_guard.model.ActionTaken;
import com.krish.sentinel_guard.model.AuditLog;
import com.krish.sentinel_guard.model.SecurityIncident;
import com.krish.sentinel_guard.model.UserRole;
import com.krish.sentinel_guard.repository.AuditLogRepository;
import com.krish.sentinel_guard.repository.SecurityIncidentRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Enterprise Data Retention & Historical Telemetry Maintenance Service.
 * Enforces a configurable 6-month (180-day default) historical data window
 * across supported SQL storage engines (PostgreSQL, MySQL, Disk H2).
 */
@Service
public class DataRetentionService {

    private static final Logger log = LoggerFactory.getLogger(DataRetentionService.class);

    private final SecurityIncidentRepository incidentRepository;
    private final AuditLogRepository auditLogRepository;
    private final DataSource dataSource;

    @Value("${sentinel.waf.data-retention.enabled:true}")
    private boolean retentionEnabled;

    @Value("${sentinel.waf.data-retention.days:180}")
    private int retentionDays;

    public DataRetentionService(
            SecurityIncidentRepository incidentRepository,
            AuditLogRepository auditLogRepository,
            DataSource dataSource) {
        this.incidentRepository = incidentRepository;
        this.auditLogRepository = auditLogRepository;
        this.dataSource = dataSource;
    }

    /**
     * Automated Daily Retention Sweep.
     * Defaults to running every day at 02:00 AM server time.
     */
    @Scheduled(cron = "${sentinel.waf.data-retention.cleanup-cron:0 0 2 * * *}")
    @Transactional
    public Map<String, Object> executeScheduledRetentionCleanup() {
        if (!retentionEnabled) {
            log.info("⏩ Data retention lifecycle purge is disabled in configuration.");
            return Map.of("status", "DISABLED", "purgedCount", 0);
        }

        LocalDateTime cutoff = LocalDateTime.now().minusDays(retentionDays);
        log.info("🧹 Executing automated SentinelGuard data retention cleanup (Cutoff: {} | Days: {})", cutoff, retentionDays);

        int incidentsPurged = incidentRepository.deleteByTimestampBefore(cutoff);
        int auditLogsPurged = auditLogRepository.deleteByTimestampBefore(cutoff);

        log.info("✅ Data retention cycle completed: {} incidents and {} audit logs purged older than {} days.",
                incidentsPurged, auditLogsPurged, retentionDays);

        if (incidentsPurged > 0 || auditLogsPurged > 0) {
            AuditLog cleanupLog = new AuditLog(
                    "SYSTEM_RETENTION_DAEMON",
                    UserRole.ROLE_SUPER_ADMIN,
                    null,
                    "ALL_DOMAINS",
                    "Retention Cutoff: " + cutoff + " (" + retentionDays + " days)",
                    ActionTaken.PASSED_CLEAN,
                    0,
                    0L,
                    "127.0.0.1",
                    String.format("Automated 6-month retention cycle purged %d incident records and %d audit logs.",
                            incidentsPurged, auditLogsPurged)
            );
            auditLogRepository.save(cleanupLog);
        }

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("status", "SUCCESS");
        summary.put("retentionDays", retentionDays);
        summary.put("cutoffDate", cutoff.toString());
        summary.put("incidentsPurged", incidentsPurged);
        summary.put("auditLogsPurged", auditLogsPurged);
        summary.put("executedAt", LocalDateTime.now().toString());

        return summary;
    }

    /**
     * Manual Trigger for Data Retention Purge (for Super Admins).
     */
    @Transactional
    public Map<String, Object> manualPurge(String initiatedBy, Integer customDays) {
        int days = (customDays != null && customDays > 0) ? customDays : retentionDays;
        LocalDateTime cutoff = LocalDateTime.now().minusDays(days);

        int incidentsPurged = incidentRepository.deleteByTimestampBefore(cutoff);
        int auditLogsPurged = auditLogRepository.deleteByTimestampBefore(cutoff);

        AuditLog manualLog = new AuditLog(
                initiatedBy != null ? initiatedBy : "ADMIN",
                UserRole.ROLE_SUPER_ADMIN,
                null,
                "ALL_DOMAINS",
                "Manual Retention Purge: " + days + " days threshold",
                ActionTaken.PASSED_CLEAN,
                0,
                0L,
                "127.0.0.1",
                String.format("Manual data retention purge executed by %s. Purged %d incidents and %d audit records older than %d days.",
                        initiatedBy, incidentsPurged, auditLogsPurged, days)
        );
        auditLogRepository.save(manualLog);

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("status", "SUCCESS");
        summary.put("initiatedBy", initiatedBy);
        summary.put("retentionDays", days);
        summary.put("cutoffDate", cutoff.toString());
        summary.put("incidentsPurged", incidentsPurged);
        summary.put("auditLogsPurged", auditLogsPurged);
        summary.put("executedAt", LocalDateTime.now().toString());

        return summary;
    }

    /**
     * Get real-time database storage metrics and data retention telemetry.
     */
    public Map<String, Object> getRetentionStats() {
        LocalDateTime cutoff = LocalDateTime.now().minusDays(retentionDays);
        long totalIncidents = incidentRepository.count();
        long expiredPending = incidentRepository.countByTimestampBefore(cutoff);

        String dbProductName = "Unknown SQL Engine";
        String dbUrl = "N/A";
        try (Connection conn = dataSource.getConnection()) {
            DatabaseMetaData meta = conn.getMetaData();
            dbProductName = meta.getDatabaseProductName() + " " + meta.getDatabaseProductVersion();
            dbUrl = meta.getURL();
        } catch (Exception e) {
            log.debug("Database metadata lookup: {}", e.getMessage());
        }

        // Get oldest and newest incident timestamp
        String oldestIncident = "N/A";
        String newestIncident = "N/A";

        List<SecurityIncident> oldestList = incidentRepository.findAll(
                PageRequest.of(0, 1, Sort.by(Sort.Direction.ASC, "timestamp"))
        ).getContent();
        if (!oldestList.isEmpty()) {
            oldestIncident = oldestList.get(0).getTimestamp().toString();
        }

        List<SecurityIncident> newestList = incidentRepository.findAll(
                PageRequest.of(0, 1, Sort.by(Sort.Direction.DESC, "timestamp"))
        ).getContent();
        if (!newestList.isEmpty()) {
            newestIncident = newestList.get(0).getTimestamp().toString();
        }

        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("retentionEnabled", retentionEnabled);
        stats.put("retentionPolicyDays", retentionDays);
        stats.put("retentionWindowDescription", retentionDays + " Days (~" + (retentionDays / 30) + " Months)");
        stats.put("currentCutoffTimestamp", cutoff.toString());
        stats.put("totalStoredIncidents", totalIncidents);
        stats.put("expiredIncidentsPendingPurge", expiredPending);
        stats.put("activeIncidentsInRetention", Math.max(0, totalIncidents - expiredPending));
        stats.put("oldestRecordedIncident", oldestIncident);
        stats.put("newestRecordedIncident", newestIncident);
        stats.put("databaseEngine", dbProductName);
        stats.put("databaseUrl", sanitizeJdbcUrl(dbUrl));

        return stats;
    }

    private String sanitizeJdbcUrl(String url) {
        if (url == null) return "N/A";
        // Strip out passwords if embedded in JDBC connection string
        return url.replaceAll("password=[^;&]*", "password=*****");
    }

    public int getRetentionDays() {
        return retentionDays;
    }
}
