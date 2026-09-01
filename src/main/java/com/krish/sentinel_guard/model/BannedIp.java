package com.krish.sentinel_guard.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "banned_ips")
public class BannedIp {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String ipAddress;

    private String country;
    private String reason;

    @Enumerated(EnumType.STRING)
    private ThreatType triggerThreatType;

    private Integer violationCount = 1;
    private LocalDateTime bannedAt;
    private LocalDateTime bannedUntil;
    private Boolean active = true;

    public BannedIp() {
        this.bannedAt = LocalDateTime.now();
    }

    public BannedIp(String ipAddress, String country, String reason, ThreatType triggerThreatType, int durationSeconds) {
        this.ipAddress = ipAddress;
        this.country = country;
        this.reason = reason;
        this.triggerThreatType = triggerThreatType;
        this.bannedAt = LocalDateTime.now();
        this.bannedUntil = LocalDateTime.now().plusSeconds(durationSeconds);
        this.active = true;
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }

    public String getCountry() { return country; }
    public void setCountry(String country) { this.country = country; }

    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }

    public ThreatType getTriggerThreatType() { return triggerThreatType; }
    public void setTriggerThreatType(ThreatType triggerThreatType) { this.triggerThreatType = triggerThreatType; }

    public Integer getViolationCount() { return violationCount; }
    public void setViolationCount(Integer violationCount) { this.violationCount = violationCount; }

    public LocalDateTime getBannedAt() { return bannedAt; }
    public void setBannedAt(LocalDateTime bannedAt) { this.bannedAt = bannedAt; }

    public LocalDateTime getBannedUntil() { return bannedUntil; }
    public void setBannedUntil(LocalDateTime bannedUntil) { this.bannedUntil = bannedUntil; }

    public Boolean getActive() { return active; }
    public void setActive(Boolean active) { this.active = active; }
}
