package com.krish.sentinel_guard.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "monitored_domains")
public class MonitoredDomain {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String domainName;

    @Column(nullable = false)
    private String displayName;

    private String primaryIp;
    private String ipv6;
    private String country;
    private String countryCode;
    private String organization;
    private String registrar;

    private String sslStatus; // VALID, EXPIRED, SELF_SIGNED, NONE
    private String sslIssuer;
    private LocalDateTime sslExpiresAt;
    private Integer sslDaysRemaining;

    private String healthStatus; // HEALTHY, WARNING, CRITICAL, UNKNOWN
    private Integer responseTimeMs;

    private Long totalRequests = 0L;
    private Long blockedRequests = 0L;
    private Long cleanRequests = 0L;

    private Boolean isProtected = true;
    private Boolean isLiveMonitoring = true;

    /** Origin backend this WAF reverse-proxies to after a clean inspection, e.g. http://127.0.0.1:8085 */
    private String originUrl;

    /** True when the domain's DNS A/AAAA records include SentinelGuard's public IP. */
    private Boolean dnsPointsToWaf = false;

    /** INLINE | DNS_PENDING | NO_ORIGIN | CONTROL_PLANE */
    private String wafProtectionStatus = "DNS_PENDING";

    private LocalDateTime createdAt;
    private LocalDateTime lastCheckedAt;

    public MonitoredDomain() {
        this.createdAt = LocalDateTime.now();
        this.lastCheckedAt = LocalDateTime.now();
    }

    public MonitoredDomain(String domainName, String displayName, String primaryIp, String country, String registrar) {
        this.domainName = domainName;
        this.displayName = displayName;
        this.primaryIp = primaryIp;
        this.country = country;
        this.registrar = registrar;
        this.createdAt = LocalDateTime.now();
        this.lastCheckedAt = LocalDateTime.now();
        this.healthStatus = "HEALTHY";
        this.sslStatus = "VALID";
        this.isProtected = true;
        this.isLiveMonitoring = true;
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getDomainName() { return domainName; }
    public void setDomainName(String domainName) { this.domainName = domainName; }

    public String getDisplayName() { return displayName; }
    public void setDisplayName(String displayName) { this.displayName = displayName; }

    public String getPrimaryIp() { return primaryIp; }
    public void setPrimaryIp(String primaryIp) { this.primaryIp = primaryIp; }

    public String getIpv6() { return ipv6; }
    public void setIpv6(String ipv6) { this.ipv6 = ipv6; }

    public String getCountry() { return country; }
    public void setCountry(String country) { this.country = country; }

    public String getCountryCode() { return countryCode; }
    public void setCountryCode(String countryCode) { this.countryCode = countryCode; }

    public String getOrganization() { return organization; }
    public void setOrganization(String organization) { this.organization = organization; }

    public String getRegistrar() { return registrar; }
    public void setRegistrar(String registrar) { this.registrar = registrar; }

    public String getSslStatus() { return sslStatus; }
    public void setSslStatus(String sslStatus) { this.sslStatus = sslStatus; }

    public String getSslIssuer() { return sslIssuer; }
    public void setSslIssuer(String sslIssuer) { this.sslIssuer = sslIssuer; }

    public LocalDateTime getSslExpiresAt() { return sslExpiresAt; }
    public void setSslExpiresAt(LocalDateTime sslExpiresAt) { this.sslExpiresAt = sslExpiresAt; }

    public Integer getSslDaysRemaining() { return sslDaysRemaining; }
    public void setSslDaysRemaining(Integer sslDaysRemaining) { this.sslDaysRemaining = sslDaysRemaining; }

    public String getHealthStatus() { return healthStatus; }
    public void setHealthStatus(String healthStatus) { this.healthStatus = healthStatus; }

    public Integer getResponseTimeMs() { return responseTimeMs; }
    public void setResponseTimeMs(Integer responseTimeMs) { this.responseTimeMs = responseTimeMs; }

    public Long getTotalRequests() { return totalRequests; }
    public void setTotalRequests(Long totalRequests) { this.totalRequests = totalRequests; }

    public Long getBlockedRequests() { return blockedRequests; }
    public void setBlockedRequests(Long blockedRequests) { this.blockedRequests = blockedRequests; }

    public Long getCleanRequests() { return cleanRequests; }
    public void setCleanRequests(Long cleanRequests) { this.cleanRequests = cleanRequests; }

    public Boolean getIsProtected() { return isProtected; }
    public void setIsProtected(Boolean isProtected) { this.isProtected = isProtected; }

    public Boolean getIsLiveMonitoring() { return isLiveMonitoring; }
    public void setIsLiveMonitoring(Boolean isLiveMonitoring) { this.isLiveMonitoring = isLiveMonitoring; }

    public String getOriginUrl() { return originUrl; }
    public void setOriginUrl(String originUrl) { this.originUrl = originUrl; }

    public Boolean getDnsPointsToWaf() { return dnsPointsToWaf; }
    public void setDnsPointsToWaf(Boolean dnsPointsToWaf) { this.dnsPointsToWaf = dnsPointsToWaf; }

    public String getWafProtectionStatus() { return wafProtectionStatus; }
    public void setWafProtectionStatus(String wafProtectionStatus) { this.wafProtectionStatus = wafProtectionStatus; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }

    public LocalDateTime getLastCheckedAt() { return lastCheckedAt; }
    public void setLastCheckedAt(LocalDateTime lastCheckedAt) { this.lastCheckedAt = lastCheckedAt; }
}
