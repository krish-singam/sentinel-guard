package com.krish.sentinel_guard.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "security_incidents", indexes = {
    @Index(name = "idx_incident_timestamp", columnList = "timestamp"),
    @Index(name = "idx_incident_domain", columnList = "domainName"),
    @Index(name = "idx_incident_threat_type", columnList = "threatType"),
    @Index(name = "idx_incident_client_ip", columnList = "clientIp"),
    @Index(name = "idx_incident_blocked", columnList = "blocked")
})
public class SecurityIncident {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long domainId;
    private String domainName;

    @Column(nullable = false)
    private String clientIp;

    private String clientCountry;
    private String clientCountryCode;
    private String clientCity;

    private String httpMethod;
    private String requestPath;
    private String queryString;

    @Enumerated(EnumType.STRING)
    private ThreatType threatType;

    @Enumerated(EnumType.STRING)
    private ThreatSeverity threatSeverity;

    @Enumerated(EnumType.STRING)
    private ActionTaken actionTaken;

    private Integer threatScore; // 0 to 100
    private String matchedRule;

    @Column(length = 2048)
    private String rawPayloadSnippet;

    private String userAgent;
    private Boolean blocked = true;

    private Boolean alertSent = false;
    private String alertChannel; // EMAIL, SMS, DISCORD, NONE

    private LocalDateTime timestamp;

    public SecurityIncident() {
        this.timestamp = LocalDateTime.now();
    }

    public SecurityIncident(String domainName, String clientIp, ThreatType threatType, ThreatSeverity threatSeverity,
                            ActionTaken actionTaken, Integer threatScore, String matchedRule, String rawPayloadSnippet,
                            String httpMethod, String requestPath) {
        this.domainName = domainName;
        this.clientIp = clientIp;
        this.threatType = threatType;
        this.threatSeverity = threatSeverity;
        this.actionTaken = actionTaken;
        this.threatScore = threatScore;
        this.matchedRule = matchedRule;
        this.rawPayloadSnippet = rawPayloadSnippet;
        this.httpMethod = httpMethod;
        this.requestPath = requestPath;
        this.blocked = actionTaken != ActionTaken.PASSED_CLEAN;
        this.timestamp = LocalDateTime.now();
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Long getDomainId() { return domainId; }
    public void setDomainId(Long domainId) { this.domainId = domainId; }

    public String getDomainName() { return domainName; }
    public void setDomainName(String domainName) { this.domainName = domainName; }

    public String getClientIp() { return clientIp; }
    public void setClientIp(String clientIp) { this.clientIp = clientIp; }

    public String getClientCountry() { return clientCountry; }
    public void setClientCountry(String clientCountry) { this.clientCountry = clientCountry; }

    public String getClientCountryCode() { return clientCountryCode; }
    public void setClientCountryCode(String clientCountryCode) { this.clientCountryCode = clientCountryCode; }

    public String getClientCity() { return clientCity; }
    public void setClientCity(String clientCity) { this.clientCity = clientCity; }

    public String getHttpMethod() { return httpMethod; }
    public void setHttpMethod(String httpMethod) { this.httpMethod = httpMethod; }

    public String getRequestPath() { return requestPath; }
    public void setRequestPath(String requestPath) { this.requestPath = requestPath; }

    public String getQueryString() { return queryString; }
    public void setQueryString(String queryString) { this.queryString = queryString; }

    public ThreatType getThreatType() { return threatType; }
    public void setThreatType(ThreatType threatType) { this.threatType = threatType; }

    public ThreatSeverity getThreatSeverity() { return threatSeverity; }
    public void setThreatSeverity(ThreatSeverity threatSeverity) { this.threatSeverity = threatSeverity; }

    public ActionTaken getActionTaken() { return actionTaken; }
    public void setActionTaken(ActionTaken actionTaken) { this.actionTaken = actionTaken; }

    public Integer getThreatScore() { return threatScore; }
    public void setThreatScore(Integer threatScore) { this.threatScore = threatScore; }

    public String getMatchedRule() { return matchedRule; }
    public void setMatchedRule(String matchedRule) { this.matchedRule = matchedRule; }

    public String getRawPayloadSnippet() { return rawPayloadSnippet; }
    public void setRawPayloadSnippet(String rawPayloadSnippet) { this.rawPayloadSnippet = rawPayloadSnippet; }

    public String getUserAgent() { return userAgent; }
    public void setUserAgent(String userAgent) { this.userAgent = userAgent; }

    public Boolean getBlocked() { return blocked; }
    public void setBlocked(Boolean blocked) { this.blocked = blocked; }

    public Boolean getAlertSent() { return alertSent; }
    public void setAlertSent(Boolean alertSent) { this.alertSent = alertSent; }

    public String getAlertChannel() { return alertChannel; }
    public void setAlertChannel(String alertChannel) { this.alertChannel = alertChannel; }

    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
}
