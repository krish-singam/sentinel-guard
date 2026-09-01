package com.krish.sentinel_guard.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.net.ssl.*;
import java.net.InetSocketAddress;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Date;
import java.util.List;

@Service
public class SslInspectorService {

    private static final Logger log = LoggerFactory.getLogger(SslInspectorService.class);

    private final WhoisService whoisService;

    public SslInspectorService(WhoisService whoisService) {
        this.whoisService = whoisService;
    }

    public record SslInspectionResult(
        String domain,
        boolean hasSsl,
        String status, // VALID, EXPIRED, EXPIRING_SOON, SELF_SIGNED, NONE, PORT_443_CLOSED
        String subjectCn,
        String issuer,
        LocalDateTime validFrom,
        LocalDateTime validTo,
        long daysRemaining,
        String tlsVersion,
        String cipherSuite,
        boolean isExpiringSoon
    ) {}

    public SslInspectionResult inspectSsl(String domain) {
        String cleanDomain = sanitizeDomain(domain);

        // Step 1: Attempt direct SSL handshake on target hostname with SNI
        SslInspectionResult directResult = performTlsHandshake(cleanDomain);
        if (directResult.hasSsl()) {
            return directResult;
        }

        // Step 2: If subdomain port 443 is not yet open, check if root apex domain has SSL
        String rootDomain = whoisService.extractRootDomain(cleanDomain);
        if (!rootDomain.equalsIgnoreCase(cleanDomain)) {
            SslInspectionResult rootResult = performTlsHandshake(rootDomain);
            if (rootResult.hasSsl()) {
                return new SslInspectionResult(
                    cleanDomain,
                    true,
                    rootResult.status(),
                    rootResult.subjectCn() + " (Apex Cert)",
                    rootResult.issuer(),
                    rootResult.validFrom(),
                    rootResult.validTo(),
                    rootResult.daysRemaining(),
                    rootResult.tlsVersion(),
                    rootResult.cipherSuite(),
                    rootResult.isExpiringSoon()
                );
            }
        }

        return directResult;
    }

    private SslInspectionResult performTlsHandshake(String host) {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{new PermissiveTrustManager()}, new java.security.SecureRandom());

            SSLSocketFactory factory = sslContext.getSocketFactory();
            try (SSLSocket socket = (SSLSocket) factory.createSocket()) {
                // Configure SNI (Server Name Indication) - Crucial for modern reverse proxies & CDNs
                SSLParameters sslParameters = socket.getSSLParameters();
                try {
                    sslParameters.setServerNames(Collections.singletonList(new SNIHostName(host)));
                    socket.setSSLParameters(sslParameters);
                } catch (Exception e) {
                    log.debug("SNI not supported for {}: {}", host, e.getMessage());
                }

                socket.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
                socket.connect(new InetSocketAddress(host, 443), 4000);
                socket.setSoTimeout(4000);
                socket.startHandshake();

                SSLSession session = socket.getSession();
                Certificate[] certs = session.getPeerCertificates();

                if (certs.length > 0 && certs[0] instanceof X509Certificate x509) {
                    Date notAfter = x509.getNotAfter();
                    Date notBefore = x509.getNotBefore();

                    LocalDateTime validTo = notAfter.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
                    LocalDateTime validFrom = notBefore.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();

                    long daysRemaining = ChronoUnit.DAYS.between(LocalDateTime.now(), validTo);
                    String issuer = extractIssuerName(x509.getIssuerX500Principal().getName());
                    String subject = extractCn(x509.getSubjectX500Principal().getName());

                    String status = "VALID";
                    boolean expiringSoon = false;
                    if (daysRemaining < 0) {
                        status = "EXPIRED";
                    } else if (daysRemaining <= 14) {
                        status = "EXPIRING_SOON";
                        expiringSoon = true;
                    }

                    return new SslInspectionResult(
                        host,
                        true,
                        status,
                        subject,
                        issuer,
                        validFrom,
                        validTo,
                        Math.max(0, daysRemaining),
                        session.getProtocol(),
                        session.getCipherSuite(),
                        expiringSoon
                    );
                }
            }
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            log.warn("SSL handshake failed for {}: {}", host, msg);
            String status = msg.toLowerCase().contains("refused") ? "PORT_443_CLOSED" : "NONE";
            return new SslInspectionResult(
                host,
                false,
                status,
                "No SSL Cert Present / Host Unreachable",
                "None",
                null,
                null,
                0,
                "N/A",
                "N/A",
                false
            );
        }

        return new SslInspectionResult(
            host,
            false,
            "NONE",
            "N/A",
            "None",
            null,
            null,
            0,
            "N/A",
            "N/A",
            false
        );
    }

    private String extractCn(String dn) {
        if (dn == null) return "Unknown";
        for (String part : dn.split(",")) {
            if (part.trim().startsWith("CN=")) {
                return part.trim().substring(3).replace("\"", "");
            }
        }
        return dn;
    }

    private String extractIssuerName(String dn) {
        if (dn == null) return "Unknown";
        for (String part : dn.split(",")) {
            if (part.trim().startsWith("O=")) {
                return part.trim().substring(2).replace("\"", "");
            }
        }
        for (String part : dn.split(",")) {
            if (part.trim().startsWith("CN=")) {
                return part.trim().substring(3).replace("\"", "");
            }
        }
        return dn;
    }

    private String sanitizeDomain(String raw) {
        if (raw == null) return "";
        String s = raw.trim().toLowerCase();
        s = s.replaceFirst("^https?://", "");
        s = s.replaceFirst("/.*$", "");
        s = s.replaceFirst(":\\d+$", "");
        return s;
    }

    private static class PermissiveTrustManager implements X509TrustManager {
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
    }
}
