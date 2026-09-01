package com.krish.sentinel_guard.controller;

import com.krish.sentinel_guard.model.MonitoredDomain;
import com.krish.sentinel_guard.service.DomainIntelligenceService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/domains")
public class DomainController {

    private final DomainIntelligenceService domainService;

    public DomainController(DomainIntelligenceService domainService) {
        this.domainService = domainService;
    }

    public record AddDomainRequest(
        @NotBlank(message = "Domain name is required") String domainName,
        String displayName
    ) {}

    @GetMapping
    public ResponseEntity<List<MonitoredDomain>> getAllDomains() {
        return ResponseEntity.ok(domainService.getAllDomains());
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<MonitoredDomain> addDomain(@Valid @RequestBody AddDomainRequest request) {
        MonitoredDomain created = domainService.registerDomain(request.domainName(), request.displayName());
        return ResponseEntity.ok(created);
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
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<Void> deleteDomain(@PathVariable Long id) {
        domainService.deleteDomain(id);
        return ResponseEntity.noContent().build();
    }
}
