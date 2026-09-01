package com.krish.sentinel_guard.controller;

import com.krish.sentinel_guard.model.AuditLog;
import com.krish.sentinel_guard.repository.AuditLogRepository;
import com.krish.sentinel_guard.service.DataRetentionService;
import com.krish.sentinel_guard.service.PdfReportService;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/reports")
public class ReportController {

    private final PdfReportService pdfReportService;
    private final AuditLogRepository auditLogRepository;
    private final DataRetentionService dataRetentionService;

    public ReportController(
            PdfReportService pdfReportService,
            AuditLogRepository auditLogRepository,
            DataRetentionService dataRetentionService) {
        this.pdfReportService = pdfReportService;
        this.auditLogRepository = auditLogRepository;
        this.dataRetentionService = dataRetentionService;
    }

    @GetMapping("/pdf")
    public ResponseEntity<byte[]> downloadPdfReport() {
        try {
            byte[] pdfBytes = pdfReportService.generateSecurityAuditReport();
            String filename = "sentinelguard-report-" + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmm")) + ".pdf";

            return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                .contentType(MediaType.APPLICATION_PDF)
                .body(pdfBytes);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/audit")
    public ResponseEntity<List<AuditLog>> getAuditLogTrail() {
        return ResponseEntity.ok(auditLogRepository.findByOrderByTimestampDesc(PageRequest.of(0, 50)));
    }

    @GetMapping("/retention/stats")
    public ResponseEntity<Map<String, Object>> getRetentionStats() {
        return ResponseEntity.ok(dataRetentionService.getRetentionStats());
    }

    @PostMapping("/retention/purge")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<Map<String, Object>> triggerManualRetentionPurge(
            Authentication authentication,
            @RequestParam(required = false) Integer days) {
        String username = authentication != null ? authentication.getName() : "SUPER_ADMIN";
        Map<String, Object> result = dataRetentionService.manualPurge(username, days);
        return ResponseEntity.ok(result);
    }
}
