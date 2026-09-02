package com.krish.sentinel_guard.config;

import com.krish.sentinel_guard.model.*;
import com.krish.sentinel_guard.repository.MonitoredDomainRepository;
import com.krish.sentinel_guard.repository.UserAccountRepository;
import com.krish.sentinel_guard.service.DomainIntelligenceService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class DataInitializer implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);

    private final MonitoredDomainRepository domainRepository;
    private final UserAccountRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final DomainIntelligenceService domainIntelligenceService;
    private final String usertestingOrigin;

    public DataInitializer(
            MonitoredDomainRepository domainRepository,
            UserAccountRepository userRepository,
            PasswordEncoder passwordEncoder,
            DomainIntelligenceService domainIntelligenceService,
            @Value("${sentinel.waf.seed.usertesting-origin:http://127.0.0.1:8085}") String usertestingOrigin) {
        this.domainRepository = domainRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.domainIntelligenceService = domainIntelligenceService;
        this.usertestingOrigin = usertestingOrigin;
    }

    @Override
    public void run(String... args) {
        seedUsers();
        seedDomains();
        patchExistingDomainOrigins();
        log.info("SentinelGuard WAF & Threat Intelligence Platform initialized successfully.");
    }

    private void seedUsers() {
        if (userRepository.count() == 0) {
            userRepository.saveAll(List.of(
                new UserAccount("krishna", passwordEncoder.encode("krishna"), "Krishna Singamsetti", "krishna@singamsettikrishna.in", UserRole.ROLE_SUPER_ADMIN, "https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150"),
                new UserAccount("alex", passwordEncoder.encode("alex"), "Alex Mercer", "alex@singamsettikrishna.in", UserRole.ROLE_SECURITY_ANALYST, "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=150"),
                new UserAccount("sarah", passwordEncoder.encode("sarah"), "Sarah Connor", "sarah@singamsettikrishna.in", UserRole.ROLE_AUDITOR, "https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=150")
            ));
        }
    }

    private void seedDomains() {
        if (domainRepository.count() == 0) {
            MonitoredDomain d0 = new MonitoredDomain("sentinel-guard.singamsettikrishna.in", "SentinelGuard Production Hub", "140.245.250.50", "India", "Hostinger Operations, UAB");
            d0.setTotalRequests(0L);
            d0.setBlockedRequests(0L);
            d0.setCleanRequests(0L);
            d0.setHealthStatus("HEALTHY");
            d0.setWafProtectionStatus("CONTROL_PLANE");

            MonitoredDomain d1 = new MonitoredDomain("usertesting.singamsettikrishna.in", "UserTesting Subdomain", "140.245.250.50", "India", "Hostinger Operations, UAB");
            d1.setTotalRequests(0L);
            d1.setBlockedRequests(0L);
            d1.setCleanRequests(0L);
            d1.setHealthStatus("HEALTHY");
            d1.setOriginUrl(usertestingOrigin);
            d1.setDnsPointsToWaf(true);
            d1.setWafProtectionStatus("INLINE");

            MonitoredDomain d2 = new MonitoredDomain("singamsettikrishna.in", "Primary Portfolio WebApp", "140.245.250.50", "India", "Hostinger Operations, UAB");
            d2.setTotalRequests(0L);
            d2.setBlockedRequests(0L);
            d2.setCleanRequests(0L);
            d2.setHealthStatus("HEALTHY");

            List<MonitoredDomain> saved = domainRepository.saveAll(List.of(d0, d1, d2));

            // Asynchronously run initial real network scans (DNS, SSL, WHOIS) on startup
            Thread.ofVirtual().start(() -> {
                for (MonitoredDomain d : saved) {
                    try {
                        domainIntelligenceService.refreshDomainIntelligence(d.getId());
                    } catch (Exception e) {
                        log.debug("Initial background scan for {}: {}", d.getDomainName(), e.getMessage());
                    }
                }
            });
        }
    }

    private void patchExistingDomainOrigins() {
        domainRepository.findByDomainNameIgnoreCase("usertesting.singamsettikrishna.in").ifPresent(d -> {
            boolean dirty = false;
            if (d.getOriginUrl() == null || d.getOriginUrl().isBlank()) {
                d.setOriginUrl(usertestingOrigin);
                dirty = true;
            }
            if (!Boolean.TRUE.equals(d.getDnsPointsToWaf())) {
                d.setDnsPointsToWaf(true);
                dirty = true;
            }
            domainIntelligenceService.applyProtectionStatus(d);
            if (dirty || !"INLINE".equals(d.getWafProtectionStatus())) {
                domainRepository.save(d);
            }
        });
        domainRepository.findByDomainNameIgnoreCase("sentinel-guard.singamsettikrishna.in").ifPresent(d -> {
            if (!"CONTROL_PLANE".equals(d.getWafProtectionStatus())) {
                d.setWafProtectionStatus("CONTROL_PLANE");
                domainRepository.save(d);
            }
        });
        domainRepository.findByDomainNameIgnoreCase("singamsettikrishna.in").ifPresent(d -> {
            domainIntelligenceService.applyProtectionStatus(d);
            domainRepository.save(d);
        });
    }
}
