package com.krish.sentinel_guard.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "audit_logs", indexes = {
    @Index(name = "idx_audit_timestamp", columnList = "timestamp"),
    @Index(name = "idx_audit_performed_by", columnList = "performedBy"),
    @Index(name = "idx_audit_attack_type", columnList = "attackType"),
    @Index(name = "idx_audit_target_domain", columnList = "targetDomain")
})
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String performedBy;

    @Enumerated(EnumType.STRING)
    private UserRole role;

    @Enumerated(EnumType.STRING)
    private ThreatType attackType;

    private String targetDomain;

    @Column(length = 2048)
    private String testPayload;

    @Enumerated(EnumType.STRING)
    private ActionTaken wafAction;

    private Integer threatScore;
    private Long executionTimeMs;
    private String clientIp;
    private String outcomeDescription;

    private LocalDateTime timestamp;

    public AuditLog() {
        this.timestamp = LocalDateTime.now();
    }

    public AuditLog(String performedBy, UserRole role, ThreatType attackType, String targetDomain,
                    String testPayload, ActionTaken wafAction, Integer threatScore, Long executionTimeMs, String clientIp, String outcomeDescription) {
        this.performedBy = performedBy;
        this.role = role;
        this.attackType = attackType;
        this.targetDomain = targetDomain;
        this.testPayload = testPayload;
        this.wafAction = wafAction;
        this.threatScore = threatScore;
        this.executionTimeMs = executionTimeMs;
        this.clientIp = clientIp;
        this.outcomeDescription = outcomeDescription;
        this.timestamp = LocalDateTime.now();
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getPerformedBy() { return performedBy; }
    public void setPerformedBy(String performedBy) { this.performedBy = performedBy; }

    public UserRole getRole() { return role; }
    public void setRole(UserRole role) { this.role = role; }

    public ThreatType getAttackType() { return attackType; }
    public void setAttackType(ThreatType attackType) { this.attackType = attackType; }

    public String getTargetDomain() { return targetDomain; }
    public void setTargetDomain(String targetDomain) { this.targetDomain = targetDomain; }

    public String getTestPayload() { return testPayload; }
    public void setTestPayload(String testPayload) { this.testPayload = testPayload; }

    public ActionTaken getWafAction() { return wafAction; }
    public void setWafAction(ActionTaken wafAction) { this.wafAction = wafAction; }

    public Integer getThreatScore() { return threatScore; }
    public void setThreatScore(Integer threatScore) { this.threatScore = threatScore; }

    public Long getExecutionTimeMs() { return executionTimeMs; }
    public void setExecutionTimeMs(Long executionTimeMs) { this.executionTimeMs = executionTimeMs; }

    public String getClientIp() { return clientIp; }
    public void setClientIp(String clientIp) { this.clientIp = clientIp; }

    public String getOutcomeDescription() { return outcomeDescription; }
    public void setOutcomeDescription(String outcomeDescription) { this.outcomeDescription = outcomeDescription; }

    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
}
