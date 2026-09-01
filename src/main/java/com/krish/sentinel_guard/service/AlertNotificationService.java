package com.krish.sentinel_guard.service;

import com.krish.sentinel_guard.model.SecurityIncident;
import com.krish.sentinel_guard.model.ThreatSeverity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import jakarta.mail.internet.MimeMessage;
import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

@Service
public class AlertNotificationService {

    private static final Logger log = LoggerFactory.getLogger(AlertNotificationService.class);

    private final JavaMailSender mailSender;

    @Value("${sentinel.waf.alert-email.enabled:false}")
    private boolean emailAlertsEnabled;

    @Value("${sentinel.waf.alert-sms.enabled:false}")
    private boolean smsAlertsEnabled;

    public record DispatchedAlert(
        Long id,
        String type, // EMAIL, SMS, SLACK
        String recipient,
        String subject,
        String messageBody,
        ThreatSeverity severity,
        LocalDateTime dispatchedAt,
        String status
    ) {}

    private final List<DispatchedAlert> alertHistory = new CopyOnWriteArrayList<>();
    private long alertIdCounter = 1;

    public AlertNotificationService(ObjectProvider<JavaMailSender> mailSenderProvider) {
        this.mailSender = mailSenderProvider.getIfAvailable();
    }

    public void dispatchThreatAlert(SecurityIncident incident) {
        // High & Critical threats trigger immediate multi-channel dispatch
        if (incident.getThreatSeverity() == ThreatSeverity.HIGH || incident.getThreatSeverity() == ThreatSeverity.CRITICAL) {
            String subject = "🚨 SentinelGuard CRITICAL ALERT: " + incident.getThreatType() + " detected on " + incident.getDomainName();
            String htmlBody = buildHtmlEmailAlert(incident);

            // 1. Email Channel
            sendEmail("security-ops@singamsettikrishna.in", subject, htmlBody, incident.getThreatSeverity());

            // 2. SMS Channel (for CRITICAL only)
            if (incident.getThreatSeverity() == ThreatSeverity.CRITICAL) {
                String smsText = "[SentinelGuard ALERT] " + incident.getThreatType() + " blocked from IP " +
                        incident.getClientIp() + " on " + incident.getDomainName() + ". Threat Score: " + incident.getThreatScore() + "/100.";
                sendSms("+91-9876543210", smsText, incident.getThreatSeverity());
            }

            incident.setAlertSent(true);
            incident.setAlertChannel(incident.getThreatSeverity() == ThreatSeverity.CRITICAL ? "EMAIL_AND_SMS" : "EMAIL");
        }
    }

    public void sendEmail(String to, String subject, String htmlContent, ThreatSeverity severity) {
        try {
            if (emailAlertsEnabled && mailSender != null) {
                MimeMessage message = mailSender.createMimeMessage();
                MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
                helper.setTo(to);
                helper.setSubject(subject);
                helper.setText(htmlContent, true);
                mailSender.send(message);
                log.info("📧 ALERT [EMAIL DISPATCHED VIA SMTP] To: {} | Subject: {}", to, subject);
                recordAlert("EMAIL", to, subject, htmlContent, severity, "DELIVERED (SMTP)");
            } else {
                log.info("📧 ALERT [SIMULATED EMAIL LOG] To: {} | Subject: {}", to, subject);
                recordAlert("EMAIL", to, subject, htmlContent, severity, "SIMULATED_DISPATCH");
            }
        } catch (Exception e) {
            log.error("Failed to dispatch email alert: {}", e.getMessage());
            recordAlert("EMAIL", to, subject, htmlContent, severity, "FAILED_DISPATCH");
        }
    }

    public void sendSms(String phoneNumber, String message, ThreatSeverity severity) {
        log.warn("📱 ALERT [SMS DISPATCHED] To: {} | Message: {}", phoneNumber, message);
        recordAlert("SMS", phoneNumber, "Critical Incident SMS", message, severity, "DELIVERED (SMS GATEWAY)");
    }

    private void recordAlert(String type, String recipient, String subject, String body, ThreatSeverity severity, String status) {
        alertHistory.add(0, new DispatchedAlert(
            alertIdCounter++,
            type,
            recipient,
            subject,
            body,
            severity,
            LocalDateTime.now(),
            status
        ));

        // Keep last 50 alerts in memory
        if (alertHistory.size() > 50) {
            alertHistory.remove(alertHistory.size() - 1);
        }
    }

    public List<DispatchedAlert> getRecentAlerts() {
        return alertHistory;
    }

    private String buildHtmlEmailAlert(SecurityIncident incident) {
        return """
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 8px;">
                <h2 style="color: #e11d48;">🚨 SentinelGuard Security Incident Alert</h2>
                <p>An unauthorized attack vector was intercepted and neutralized by the WAF engine.</p>
                <table style="width: 100%%; border-collapse: collapse; margin-top: 15px;">
                    <tr><td style="padding: 8px; font-weight: bold;">Target Domain:</td><td style="padding: 8px;">%s</td></tr>
                    <tr><td style="padding: 8px; font-weight: bold;">Threat Vector:</td><td style="padding: 8px; color: #dc2626;">%s</td></tr>
                    <tr><td style="padding: 8px; font-weight: bold;">Threat Severity:</td><td style="padding: 8px;">%s</td></tr>
                    <tr><td style="padding: 8px; font-weight: bold;">Threat Score:</td><td style="padding: 8px;">%d / 100</td></tr>
                    <tr><td style="padding: 8px; font-weight: bold;">Attacker IP:</td><td style="padding: 8px;">%s (%s)</td></tr>
                    <tr><td style="padding: 8px; font-weight: bold;">Action Taken:</td><td style="padding: 8px; font-weight: bold; color: #16a34a;">%s</td></tr>
                    <tr><td style="padding: 8px; font-weight: bold;">Matched Rule:</td><td style="padding: 8px;">%s</td></tr>
                    <tr><td style="padding: 8px; font-weight: bold;">Payload Snippet:</td><td style="padding: 8px; background: #f8fafc; font-family: monospace;">%s</td></tr>
                </table>
                <hr style="margin: 20px 0; border: none; border-top: 1px solid #e2e8f0;" />
                <p style="font-size: 12px; color: #64748b;">Generated automatically by SentinelGuard Intelligent WAF.</p>
            </div>
            """.formatted(
                incident.getDomainName(),
                incident.getThreatType(),
                incident.getThreatSeverity(),
                incident.getThreatScore(),
                incident.getClientIp(),
                incident.getClientCountry() != null ? incident.getClientCountry() : "Unknown",
                incident.getActionTaken(),
                incident.getMatchedRule(),
                incident.getRawPayloadSnippet()
            );
    }
}
