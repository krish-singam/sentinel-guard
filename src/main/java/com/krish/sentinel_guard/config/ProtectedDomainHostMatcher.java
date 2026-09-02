package com.krish.sentinel_guard.config;

import com.krish.sentinel_guard.service.WafHostClassificationService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;

@Component
public class ProtectedDomainHostMatcher implements RequestMatcher {

    private final WafHostClassificationService hostClassification;

    public ProtectedDomainHostMatcher(WafHostClassificationService hostClassification) {
        this.hostClassification = hostClassification;
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        return hostClassification.isDataPlaneProtectedHost(hostClassification.resolveHost(request));
    }
}
