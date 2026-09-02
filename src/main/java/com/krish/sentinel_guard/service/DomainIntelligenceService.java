package com.krish.sentinel_guard.service;

import com.krish.sentinel_guard.model.MonitoredDomain;
import com.krish.sentinel_guard.repository.MonitoredDomainRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
public class DomainIntelligenceService {

    private static final Logger log = LoggerFactory.getLogger(DomainIntelligenceService.class);

    private final MonitoredDomainRepository domainRepository;
    private final DnsLookupService dnsLookupService;
    private final WhoisService whoisService;
    private final SslInspectorService sslInspectorService;
    private final GeoIpService geoIpService;
    private final WafPublicIdentityService wafPublicIdentityService;

    public DomainIntelligenceService(
            MonitoredDomainRepository domainRepository,
            DnsLookupService dnsLookupService,
            WhoisService whoisService,
            SslInspectorService sslInspectorService,
            GeoIpService geoIpService,
            WafPublicIdentityService wafPublicIdentityService) {
        this.domainRepository = domainRepository;
        this.dnsLookupService = dnsLookupService;
        this.whoisService = whoisService;
        this.sslInspectorService = sslInspectorService;
        this.geoIpService = geoIpService;
        this.wafPublicIdentityService = wafPublicIdentityService;
    }

    public record FullDomainReport(
        MonitoredDomain domain,
        DnsLookupService.DnsInspectionResult dns,
        WhoisService.WhoisResult whois,
        SslInspectorService.SslInspectionResult ssl,
        GeoIpService.GeoLocation geo,
        int healthScore
    ) {}

    @Transactional
    public MonitoredDomain registerDomain(String rawDomain, String displayName) {
        return registerDomain(rawDomain, displayName, null);
    }

    @Transactional
    public MonitoredDomain registerDomain(String rawDomain, String displayName, String originUrl) {
        String cleanDomain = sanitizeDomain(rawDomain);
        Optional<MonitoredDomain> existing = domainRepository.findByDomainNameIgnoreCase(cleanDomain);
        if (existing.isPresent()) {
            MonitoredDomain domain = existing.get();
            if (originUrl != null && !originUrl.isBlank()) {
                domain.setOriginUrl(OriginUrlValidator.sanitize(originUrl));
                applyProtectionStatus(domain);
                return domainRepository.save(domain);
            }
            return domain;
        }

        MonitoredDomain domain = new MonitoredDomain();
        domain.setDomainName(cleanDomain);
        domain.setDisplayName(displayName != null && !displayName.trim().isEmpty() ? displayName : cleanDomain);
        domain.setOriginUrl(OriginUrlValidator.sanitize(originUrl));
        applyProtectionStatus(domain);
        domain = domainRepository.save(domain);

        refreshDomainIntelligence(domain.getId());
        return domain;
    }

    @Transactional
    public MonitoredDomain updateDomain(Long id, String displayName, String originUrl, Boolean isProtected) {
        MonitoredDomain domain = domainRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Domain not found: " + id));
        if (displayName != null && !displayName.isBlank()) {
            domain.setDisplayName(displayName.trim());
        }
        if (originUrl != null) {
            domain.setOriginUrl(originUrl.isBlank() ? null : OriginUrlValidator.sanitize(originUrl));
        }
        if (isProtected != null) {
            domain.setIsProtected(isProtected);
        }
        applyProtectionStatus(domain);
        return domainRepository.save(domain);
    }

    /**
     * First-seen Host on this WAF IP (any DNS provider). Fast path: no blocking WHOIS/SSL.
     * Background intel refresh verifies A-record against SentinelGuard's public IP.
     */
    @Transactional
    public MonitoredDomain ensureInboundHost(String rawHost) {
        String cleanDomain = sanitizeDomain(rawHost);
        if (cleanDomain.isBlank() || cleanDomain.equals("unknown") || cleanDomain.equals("0.0.0.0")) {
            throw new IllegalArgumentException("Invalid inbound host");
        }

        Optional<MonitoredDomain> existing = domainRepository.findByDomainNameIgnoreCase(cleanDomain);
        if (existing.isPresent()) {
            return existing.get();
        }
        if (cleanDomain.startsWith("www.")) {
            Optional<MonitoredDomain> apex = domainRepository.findByDomainNameIgnoreCase(cleanDomain.substring(4));
            if (apex.isPresent()) {
                return apex.get();
            }
        }

        try {
            MonitoredDomain domain = new MonitoredDomain();
            domain.setDomainName(cleanDomain);
            domain.setDisplayName(cleanDomain);
            domain.setIsProtected(true);
            domain.setDnsPointsToWaf(true);
            domain.setWafProtectionStatus("NO_ORIGIN");
            domain.setHealthStatus("UNKNOWN");
            MonitoredDomain saved = domainRepository.save(domain);
            Thread.ofVirtual().start(() -> {
                try {
                    refreshDomainIntelligence(saved.getId());
                } catch (Exception e) {
                    log.debug("Background intel for inbound host {}: {}", cleanDomain, e.getMessage());
                }
            });
            return saved;
        } catch (DataIntegrityViolationException e) {
            return domainRepository.findByDomainNameIgnoreCase(cleanDomain)
                    .orElseThrow(() -> e);
        }
    }

    @Transactional
    public MonitoredDomain refreshDomainIntelligence(Long domainId) {
        MonitoredDomain domain = domainRepository.findById(domainId)
            .orElseThrow(() -> new IllegalArgumentException("Domain not found: " + domainId));

        String domainName = domain.getDomainName();

        // 1. DNS Lookup
        DnsLookupService.DnsInspectionResult dns = dnsLookupService.inspectDomain(domainName);
        domain.setPrimaryIp(dns.primaryIp());
        domain.setResponseTimeMs((int) dns.resolutionTimeMs());
        if (!dns.ipv6List().isEmpty()) {
            domain.setIpv6(dns.ipv6List().get(0));
        }

        domain.setDnsPointsToWaf(wafPublicIdentityService.pointsToWaf(dns.ipv4List(), dns.ipv6List()));
        applyProtectionStatus(domain);

        // 2. GeoIP lookup
        if (dns.reachable() && !"Unknown".equals(dns.primaryIp())) {
            GeoIpService.GeoLocation geo = geoIpService.resolve(dns.primaryIp());
            domain.setCountry(geo.country());
            domain.setCountryCode(geo.countryCode());
            domain.setOrganization(geo.org());
        }

        // 3. WHOIS lookup
        WhoisService.WhoisResult whois = whoisService.queryWhois(domainName);
        if (whois.success()) {
            domain.setRegistrar(whois.registrar());
        }

        // 4. SSL Inspection
        SslInspectorService.SslInspectionResult ssl = sslInspectorService.inspectSsl(domainName);
        domain.setSslStatus(ssl.status());
        domain.setSslIssuer(ssl.issuer());
        domain.setSslExpiresAt(ssl.validTo());
        domain.setSslDaysRemaining((int) ssl.daysRemaining());

        // 5. Health Status Calculation
        if (!dns.reachable()) {
            domain.setHealthStatus("CRITICAL");
        } else if ("EXPIRED".equals(ssl.status()) || (ssl.daysRemaining() > 0 && ssl.daysRemaining() < 7)) {
            domain.setHealthStatus("WARNING");
        } else {
            domain.setHealthStatus("HEALTHY");
        }

        domain.setLastCheckedAt(LocalDateTime.now());
        return domainRepository.save(domain);
    }

    public FullDomainReport getFullReport(Long domainId) {
        MonitoredDomain domain = domainRepository.findById(domainId)
            .orElseThrow(() -> new IllegalArgumentException("Domain not found: " + domainId));

        String domainName = domain.getDomainName();
        DnsLookupService.DnsInspectionResult dns = dnsLookupService.inspectDomain(domainName);
        WhoisService.WhoisResult whois = whoisService.queryWhois(domainName);
        SslInspectorService.SslInspectionResult ssl = sslInspectorService.inspectSsl(domainName);
        GeoIpService.GeoLocation geo = geoIpService.resolve(domain.getPrimaryIp());

        int healthScore = calculateHealthScore(dns, ssl, whois);

        return new FullDomainReport(domain, dns, whois, ssl, geo, healthScore);
    }

    public List<MonitoredDomain> getAllDomains() {
        return domainRepository.findAllByOrderByIdAsc();
    }

    @Transactional
    public void deleteDomain(Long id) {
        domainRepository.deleteById(id);
    }

    private int calculateHealthScore(DnsLookupService.DnsInspectionResult dns, SslInspectorService.SslInspectionResult ssl, WhoisService.WhoisResult whois) {
        int score = 100;
        if (!dns.reachable()) score -= 50;
        if (!ssl.hasSsl()) score -= 30;
        else if (ssl.isExpiringSoon()) score -= 15;
        if (dns.allRecords().stream().noneMatch(r -> "MX".equals(r.type()))) score -= 5;
        if (dns.resolutionTimeMs() > 500) score -= 10;
        return Math.max(10, Math.min(100, score));
    }

    public void applyProtectionStatus(MonitoredDomain domain) {
        if (domain == null) {
            return;
        }
        String name = domain.getDomainName() != null ? domain.getDomainName().toLowerCase() : "";
        if (name.startsWith("sentinel-guard.")) {
            domain.setWafProtectionStatus("CONTROL_PLANE");
            return;
        }
        boolean hasOrigin = domain.getOriginUrl() != null && !domain.getOriginUrl().isBlank();
        if (!hasOrigin) {
            domain.setWafProtectionStatus("NO_ORIGIN");
            return;
        }
        if (Boolean.TRUE.equals(domain.getDnsPointsToWaf())) {
            domain.setWafProtectionStatus("INLINE");
        } else {
            domain.setWafProtectionStatus("DNS_PENDING");
        }
    }

    private String sanitizeDomain(String raw) {
        if (raw == null) return "";
        String s = raw.trim().toLowerCase();
        s = s.replaceFirst("^https?://", "");
        s = s.replaceFirst("/.*$", "");
        s = s.replaceFirst(":\\d+$", "");
        return s;
    }
}
