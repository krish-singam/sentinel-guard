package com.krish.sentinel_guard.service;

import com.krish.sentinel_guard.model.MonitoredDomain;
import com.krish.sentinel_guard.model.SecurityIncident;
import com.krish.sentinel_guard.repository.MonitoredDomainRepository;
import com.krish.sentinel_guard.repository.SecurityIncidentRepository;
import com.lowagie.text.*;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Service
public class PdfReportService {

    private final MonitoredDomainRepository domainRepository;
    private final SecurityIncidentRepository incidentRepository;

    public PdfReportService(MonitoredDomainRepository domainRepository, SecurityIncidentRepository incidentRepository) {
        this.domainRepository = domainRepository;
        this.incidentRepository = incidentRepository;
    }

    public byte[] generateSecurityAuditReport() throws DocumentException {
        Document document = new Document(PageSize.A4, 36, 36, 40, 40);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PdfWriter.getInstance(document, out);

        document.open();

        // Fonts
        Font titleFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 20, new Color(15, 23, 42));
        Font subtitleFont = FontFactory.getFont(FontFactory.HELVETICA, 10, new Color(100, 116, 139));
        Font headerFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 12, new Color(30, 41, 59));
        Font cellBold = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 9, Color.WHITE);
        Font cellText = FontFactory.getFont(FontFactory.HELVETICA, 8, new Color(51, 65, 85));

        // 1. Header Banner
        Paragraph title = new Paragraph("🛡️ SentinelGuard Executive Security Report", titleFont);
        title.setSpacingAfter(4);
        document.add(title);

        Paragraph sub = new Paragraph("Generated on: " + java.time.LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")) +
                " | Target Scope: All Active Domains & WAF Engine", subtitleFont);
        sub.setSpacingAfter(18);
        document.add(sub);

        // 2. High-Level Summary Metrics
        long totalBlocked = incidentRepository.countByBlockedTrue();
        List<MonitoredDomain> domains = domainRepository.findAllByOrderByIdAsc();

        PdfPTable summaryTable = new PdfPTable(3);
        summaryTable.setWidthPercentage(100);
        summaryTable.setSpacingAfter(18);

        addSummaryCard(summaryTable, "Active Protected Domains", String.valueOf(domains.size()), new Color(59, 130, 246));
        addSummaryCard(summaryTable, "Neutralized Attacks", String.valueOf(totalBlocked), new Color(239, 68, 68));
        addSummaryCard(summaryTable, "WAF Engine Status", "100% OPERATIONAL", new Color(34, 197, 94));

        document.add(summaryTable);

        // 3. Monitored Domains Health Table
        Paragraph domainHeader = new Paragraph("🌐 Monitored DNS & Domain Health Status", headerFont);
        domainHeader.setSpacingAfter(8);
        document.add(domainHeader);

        PdfPTable domainTable = new PdfPTable(5);
        domainTable.setWidthPercentage(100);
        domainTable.setWidths(new float[]{3f, 2f, 2f, 2f, 2f});
        domainTable.setSpacingAfter(18);

        String[] dHeaders = {"Domain Name", "Primary IP", "Country", "SSL Status", "WAF State"};
        for (String h : dHeaders) {
            PdfPCell cell = new PdfPCell(new Phrase(h, cellBold));
            cell.setBackgroundColor(new Color(30, 41, 59));
            cell.setPadding(6);
            domainTable.addCell(cell);
        }

        for (MonitoredDomain d : domains) {
            domainTable.addCell(new PdfPCell(new Phrase(d.getDomainName(), cellText)));
            domainTable.addCell(new PdfPCell(new Phrase(d.getPrimaryIp() != null ? d.getPrimaryIp() : "N/A", cellText)));
            domainTable.addCell(new PdfPCell(new Phrase(d.getCountry() != null ? d.getCountry() : "Global", cellText)));
            domainTable.addCell(new PdfPCell(new Phrase(d.getSslStatus() != null ? d.getSslStatus() : "NONE", cellText)));
            domainTable.addCell(new PdfPCell(new Phrase(d.getIsProtected() ? "PROTECTED" : "BYPASSED", cellText)));
        }
        document.add(domainTable);

        // 4. Recent Security Incidents Table
        Paragraph incidentHeader = new Paragraph("🚨 Recent Intercepted Security Incidents & Attack Vectors", headerFont);
        incidentHeader.setSpacingAfter(8);
        document.add(incidentHeader);

        List<SecurityIncident> incidents = incidentRepository.findByOrderByTimestampDesc(PageRequest.of(0, 15));
        PdfPTable incidentTable = new PdfPTable(6);
        incidentTable.setWidthPercentage(100);
        incidentTable.setWidths(new float[]{2f, 2.5f, 1.5f, 2f, 1.5f, 3f});

        String[] iHeaders = {"Timestamp", "Threat Type", "Severity", "Attacker IP", "Action", "Matched Rule"};
        for (String h : iHeaders) {
            PdfPCell cell = new PdfPCell(new Phrase(h, cellBold));
            cell.setBackgroundColor(new Color(225, 29, 72));
            cell.setPadding(6);
            incidentTable.addCell(cell);
        }

        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("HH:mm:ss");
        for (SecurityIncident i : incidents) {
            incidentTable.addCell(new PdfPCell(new Phrase(i.getTimestamp().format(dtf), cellText)));
            incidentTable.addCell(new PdfPCell(new Phrase(i.getThreatType().name(), cellText)));
            incidentTable.addCell(new PdfPCell(new Phrase(i.getThreatSeverity().name(), cellText)));
            incidentTable.addCell(new PdfPCell(new Phrase(i.getClientIp(), cellText)));
            incidentTable.addCell(new PdfPCell(new Phrase(i.getActionTaken().name(), cellText)));
            incidentTable.addCell(new PdfPCell(new Phrase(i.getMatchedRule() != null ? i.getMatchedRule() : "WAF_CUSTOM", cellText)));
        }
        document.add(incidentTable);

        document.close();
        return out.toByteArray();
    }

    private void addSummaryCard(PdfPTable table, String label, String value, Color color) {
        PdfPCell cell = new PdfPCell();
        cell.setBackgroundColor(new Color(248, 250, 252));
        cell.setPadding(10);
        cell.setBorderColor(new Color(226, 232, 240));

        Font lblFont = FontFactory.getFont(FontFactory.HELVETICA, 8, new Color(100, 116, 139));
        Font valFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 14, color);

        Paragraph pLbl = new Paragraph(label, lblFont);
        Paragraph pVal = new Paragraph(value, valFont);
        cell.addElement(pLbl);
        cell.addElement(pVal);
        table.addCell(cell);
    }
}
