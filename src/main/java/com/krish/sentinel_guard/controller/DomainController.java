package com.krish.sentinel_guard.controller;

import com.krish.sentinel_guard.model.MonitoredDomain;
import com.krish.sentinel_guard.service.DomainIntelligenceService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/domains")
public class DomainController {

    private final DomainIntelligenceService domainService;

    public DomainController(DomainIntelligenceService domainService) {
        this.domainService = domainService;
    }

    public record AddDomainRequest(
        @NotBlank(message = "Domain name is required") String domainName,
        String displayName,
        String originUrl
    ) {}

    public record UpdateDomainRequest(
        String displayName,
        String originUrl,
        Boolean isProtected
    ) {}

    @GetMapping
    public ResponseEntity<List<MonitoredDomain>> getAllDomains() {
        return ResponseEntity.ok(domainService.getAllDomains());
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<?> addDomain(@Valid @RequestBody AddDomainRequest request) {
        try {
            MonitoredDomain created = domainService.registerDomain(
                    request.domainName(), request.displayName(), request.originUrl());
            return ResponseEntity.ok(created);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<?> updateDomain(
            @PathVariable Long id,
            @RequestBody UpdateDomainRequest request) {
        try {
            MonitoredDomain updated = domainService.updateDomain(
                    id, request.displayName(), request.originUrl(), request.isProtected());
            return ResponseEntity.ok(updated);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/{id}/report")
    public ResponseEntity<DomainIntelligenceService.FullDomainReport> getDomainReport(@PathVariable Long id) {
        return ResponseEntity.ok(domainService.getFullReport(id));
    }

    @PostMapping("/{id}/refresh")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<MonitoredDomain> refreshDomain(@PathVariable Long id) {
        return ResponseEntity.ok(domainService.refreshDomainIntelligence(id));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<Void> deleteDomain(@PathVariable Long id) {
        domainService.deleteDomain(id);
        return ResponseEntity.noContent().build();
    }
}
