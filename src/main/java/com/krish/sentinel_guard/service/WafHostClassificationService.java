package com.krish.sentinel_guard.service;

import com.krish.sentinel_guard.model.MonitoredDomain;
import com.krish.sentinel_guard.repository.MonitoredDomainRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class WafHostClassificationService {

    private final MonitoredDomainRepository domainRepository;
    private final Set<String> controlPlaneHosts;

    public WafHostClassificationService(
            MonitoredDomainRepository domainRepository,
            @Value("${sentinel.waf.control-plane-hosts:sentinel-guard.singamsettikrishna.in}") String controlPlaneHosts) {
        this.domainRepository = domainRepository;
        this.controlPlaneHosts = Arrays.stream(controlPlaneHosts.split(","))
                .map(String::trim)
                .map(s -> s.toLowerCase(Locale.ROOT))
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toSet());
    }

    public String resolveHost(HttpServletRequest request) {
        String host = request.getHeader("X-Forwarded-Host");
        if (host == null || host.isBlank()) {
            host = request.getHeader("Host");
        }
        if (host == null || host.isBlank()) {
            host = request.getServerName();
        }
        return sanitizeHost(host);
    }

    public String sanitizeHost(String host) {
        if (host == null) {
            return "";
        }
        String h = host.split(",")[0].trim().toLowerCase(Locale.ROOT);
        if (h.startsWith("[") && h.contains("]")) {
            return h.substring(1, h.indexOf(']'));
        }
        int colon = h.indexOf(':');
        if (colon > 0) {
            h = h.substring(0, colon);
        }
        return h;
    }

    public boolean looksLikeLiteralIp(String host) {
        String h = sanitizeHost(host);
        if (h.isEmpty()) {
            return true;
        }
        if (h.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
            return true;
        }
        return h.contains(":");
    }

    public boolean isControlPlaneHost(String host) {
        String h = sanitizeHost(host);
        if (h.isEmpty()) {
            return true;
        }
        if ("localhost".equals(h) || "127.0.0.1".equals(h) || "::1".equals(h) || "0:0:0:0:0:0:0:1".equals(h)) {
            return true;
        }
        if (controlPlaneHosts.contains(h) || h.startsWith("sentinel-guard.")) {
            return true;
        }
        return findDomain(h)
                .map(d -> "CONTROL_PLANE".equalsIgnoreCase(d.getWafProtectionStatus()))
                .orElse(false);
    }

    public Optional<MonitoredDomain> findDomain(String host) {
        String h = sanitizeHost(host);
        if (h.isEmpty()) {
            return Optional.empty();
        }
        Optional<MonitoredDomain> exact = domainRepository.findByDomainNameIgnoreCase(h);
        if (exact.isPresent()) {
            return exact;
        }
        if (h.startsWith("www.")) {
            return domainRepository.findByDomainNameIgnoreCase(h.substring(4));
        }
        return Optional.empty();
    }

    public boolean isDataPlaneHost(String host) {
        return !isControlPlaneHost(host);
    }

    public boolean isDataPlaneProtectedHost(String host) {
        return isDataPlaneHost(host);
    }
}
