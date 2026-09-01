package com.krish.sentinel_guard.service;

import com.krish.sentinel_guard.model.MonitoredDomain;
import com.krish.sentinel_guard.repository.MonitoredDomainRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    public DomainIntelligenceService(
            MonitoredDomainRepository domainRepository,
            DnsLookupService dnsLookupService,
            WhoisService whoisService,
            SslInspectorService sslInspectorService,
            GeoIpService geoIpService) {
        this.domainRepository = domainRepository;
        this.dnsLookupService = dnsLookupService;
        this.whoisService = whoisService;
        this.sslInspectorService = sslInspectorService;
        this.geoIpService = geoIpService;
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
        String cleanDomain = sanitizeDomain(rawDomain);
        Optional<MonitoredDomain> existing = domainRepository.findByDomainNameIgnoreCase(cleanDomain);
        if (existing.isPresent()) {
            return existing.get();
        }

        MonitoredDomain domain = new MonitoredDomain();
        domain.setDomainName(cleanDomain);
        domain.setDisplayName(displayName != null && !displayName.trim().isEmpty() ? displayName : cleanDomain);
        domain = domainRepository.save(domain);

        // Perform async initial analysis
        refreshDomainIntelligence(domain.getId());
        return domain;
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
        return domainRepository.findAll();
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

    private String sanitizeDomain(String raw) {
        if (raw == null) return "";
        String s = raw.trim().toLowerCase();
        s = s.replaceFirst("^https?://", "");
        s = s.replaceFirst("/.*$", "");
        s = s.replaceFirst(":\\d+$", "");
        return s;
    }
}
