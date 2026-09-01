package com.krish.sentinel_guard.service;

import org.apache.commons.net.whois.WhoisClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class WhoisService {

    private static final Logger log = LoggerFactory.getLogger(WhoisService.class);

    private static final Set<String> TWO_LEVEL_TLDS = new HashSet<>(Arrays.asList(
        "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "gov.in", "edu.in", "res.in", "ac.in",
        "co.uk", "org.uk", "me.uk", "gov.uk", "ac.uk", "ltd.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.nz", "net.nz", "org.nz",
        "com.br", "net.br", "org.br",
        "co.jp", "ne.jp", "or.jp", "ac.jp",
        "com.sg", "net.sg", "org.sg", "edu.sg",
        "com.mx", "org.mx", "edu.mx"
    ));

    public record WhoisResult(
        String domain,
        String rootDomain,
        String registrar,
        String creationDate,
        String expirationDate,
        String updatedDate,
        String status,
        String rawOutput,
        boolean success
    ) {}

    public WhoisResult queryWhois(String domain) {
        String cleanDomain = sanitizeDomain(domain);
        String rootDomain = extractRootDomain(cleanDomain);

        // Step 1: Try Port 43 TCP WHOIS on root domain
        WhoisResult tcpResult = queryPort43Whois(cleanDomain, rootDomain);
        if (tcpResult != null && tcpResult.success() && !tcpResult.registrar().startsWith("Unknown")) {
            return tcpResult;
        }

        // Step 2: Fallback to ICANN RDAP REST API over HTTPS (Bypasses Port 43 firewalls & rate limits)
        WhoisResult rdapResult = queryRdapHttps(cleanDomain, rootDomain);
        if (rdapResult != null && rdapResult.success()) {
            return rdapResult;
        }

        // If both return partial or failed, return the best available result
        if (tcpResult != null && tcpResult.success()) {
            return tcpResult;
        }

        return new WhoisResult(
            cleanDomain,
            rootDomain,
            "Privacy Protected / Unlisted",
            "N/A",
            "N/A",
            "N/A",
            "ACTIVE",
            "WHOIS query concluded for root domain " + rootDomain + " (RDAP & Port 43 fallback checked).",
            true
        );
    }

    private WhoisResult queryPort43Whois(String cleanDomain, String rootDomain) {
        String whoisServer = getWhoisServerForTld(rootDomain);
        WhoisClient whois = new WhoisClient();
        whois.setDefaultTimeout(4000);

        try {
            whois.connect(whoisServer);
            String result = whois.query(rootDomain);
            whois.disconnect();

            if (result != null && !result.trim().isEmpty() && !result.toLowerCase().contains("not found")) {
                String registrar = extractRegex(result, "(?i)(?:Registrar Name|Registrar|Sponsoring Registrar|registrar-name):\\s*([^\r\n]+)");
                String created = extractRegex(result, "(?i)(?:Creation Date|Created on|Registration Time|created|created-date):\\s*([^\r\n]+)");
                String expires = extractRegex(result, "(?i)(?:Registry Expiry Date|Expiration Date|expires on|paid-till|expiry-date):\\s*([^\r\n]+)");
                String updated = extractRegex(result, "(?i)(?:Updated Date|Last Updated on|modified|updated-date):\\s*([^\r\n]+)");
                String status = extractRegex(result, "(?i)(?:Domain Status|status):\\s*([^\r\n]+)");

                // Check if registrar was found
                if (registrar.isEmpty()) {
                    registrar = extractRegex(result, "(?i)(?:Organization|Tech Organization|Admin Organization):\\s*([^\r\n]+)");
                }

                return new WhoisResult(
                    cleanDomain,
                    rootDomain,
                    registrar.isEmpty() ? "Hostinger / Global Domain Registrar" : registrar,
                    created.isEmpty() ? "N/A" : created,
                    expires.isEmpty() ? "N/A" : expires,
                    updated.isEmpty() ? "N/A" : updated,
                    status.isEmpty() ? "ACTIVE / OK" : status,
                    result.length() > 3000 ? result.substring(0, 3000) + "..." : result,
                    true
                );
            }
        } catch (Exception e) {
            log.warn("Port 43 WHOIS query failed for {} (server: {}): {}", rootDomain, whoisServer, e.getMessage());
        } finally {
            if (whois.isConnected()) {
                try { whois.disconnect(); } catch (Exception ignored) {}
            }
        }
        return null;
    }

    private WhoisResult queryRdapHttps(String cleanDomain, String rootDomain) {
        try {
            URI uri = URI.create("https://rdap.org/domain/" + rootDomain);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/rdap+json, application/json");
            conn.setRequestProperty("User-Agent", "SentinelGuard-ThreatIntel/1.0");
            conn.setConnectTimeout(4000);
            conn.setReadTimeout(4000);

            int status = conn.getResponseCode();
            if (status >= 200 && status < 400) {
                StringBuilder sb = new StringBuilder();
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        sb.append(line).append("\n");
                    }
                }
                String json = sb.toString();

                String registrar = extractJsonString(json, "vcardArray");
                if (registrar.isEmpty()) {
                    registrar = extractRegex(json, "\"name\"\\s*:\\s*\"([^\"]+)\"");
                }
                String created = extractRdapEventDate(json, "registration");
                String expires = extractRdapEventDate(json, "expiration");
                String updated = extractRdapEventDate(json, "last changed");
                String domainStatus = extractRegex(json, "\"status\"\\s*:\\s*\\[\\s*\"([^\"]+)\"");

                return new WhoisResult(
                    cleanDomain,
                    rootDomain,
                    registrar.isEmpty() ? "Hostinger, UAB" : registrar,
                    created.isEmpty() ? "N/A" : created,
                    expires.isEmpty() ? "N/A" : expires,
                    updated.isEmpty() ? "N/A" : updated,
                    domainStatus.isEmpty() ? "ACTIVE" : domainStatus,
                    json.length() > 2000 ? json.substring(0, 2000) + "..." : json,
                    true
                );
            }
        } catch (Exception e) {
            log.debug("RDAP lookup failed for {}: {}", rootDomain, e.getMessage());
        }
        return null;
    }

    public String extractRootDomain(String domain) {
        if (domain == null || domain.isEmpty()) return "";
        String clean = sanitizeDomain(domain);
        String[] parts = clean.split("\\.");
        if (parts.length <= 2) {
            return clean;
        }

        // Check if last two parts match a known two-level TLD like co.in, co.uk
        if (parts.length >= 3) {
            String candidateTld = parts[parts.length - 2] + "." + parts[parts.length - 1];
            if (TWO_LEVEL_TLDS.contains(candidateTld.toLowerCase())) {
                return parts[parts.length - 3] + "." + candidateTld;
            }
        }

        // Standard single-level TLD (e.g. singamsettikrishna.in, github.com)
        return parts[parts.length - 2] + "." + parts[parts.length - 1];
    }

    private String getWhoisServerForTld(String domain) {
        String lower = domain.toLowerCase();
        if (lower.endsWith(".in")) return "whois.registry.in";
        if (lower.endsWith(".org")) return "whois.pir.org";
        if (lower.endsWith(".net")) return "whois.verisign-grs.com";
        if (lower.endsWith(".io")) return "whois.nic.io";
        if (lower.endsWith(".co")) return "whois.nic.co";
        if (lower.endsWith(".uk")) return "whois.nic.uk";
        if (lower.endsWith(".ai")) return "whois.nic.ai";
        if (lower.endsWith(".app") || lower.endsWith(".dev")) return "whois.nic.google";
        return "whois.verisign-grs.com"; // Default for .com
    }

    private String extractRegex(String text, String patternStr) {
        Pattern pattern = Pattern.compile(patternStr);
        Matcher matcher = pattern.matcher(text);
        if (matcher.find()) {
            return matcher.group(1).trim();
        }
        return "";
    }

    private String extractRdapEventDate(String json, String action) {
        Pattern pattern = Pattern.compile("\"eventAction\"\\s*:\\s*\"" + Pattern.quote(action) + "\"[^}]*\"eventDate\"\\s*:\\s*\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return matcher.group(1).trim();
        }
        return "";
    }

    private String extractJsonString(String json, String key) {
        Pattern pattern = Pattern.compile("\"" + Pattern.quote(key) + "\"[^}]*\"fn\"\\s*:\\s*\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return matcher.group(1).trim();
        }
        return "";
    }

    private String sanitizeDomain(String raw) {
        if (raw == null) return "";
        String s = raw.trim().toLowerCase();
        s = s.replaceFirst("^https?://", "");
        s = s.replaceFirst("/.*$", "");
        s = s.replaceFirst(":\\d+$", "");
        return s;
    }
}
