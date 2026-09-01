package com.krish.sentinel_guard.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class GeoIpService {

    private static final Logger log = LoggerFactory.getLogger(GeoIpService.class);

    public record GeoLocation(
        String ip,
        String country,
        String countryCode,
        String city,
        String org,
        String flag
    ) {
        public static GeoLocation local(String ip) {
            return new GeoLocation(ip, "Local Network / Sandbox", "LOCAL", "Localhost", "Internal Infrastructure", "🏠");
        }
    }

    private final Map<String, GeoLocation> geoCache = new ConcurrentHashMap<>();

    public GeoLocation resolve(String ip) {
        if (ip == null || ip.trim().isEmpty() || isPrivateOrLocal(ip)) {
            return GeoLocation.local(ip != null ? ip : "127.0.0.1");
        }

        return geoCache.computeIfAbsent(ip, this::fetchGeoLocation);
    }

    private GeoLocation fetchGeoLocation(String ip) {
        try {
            // Fast JSON-free query to ip-api.com (csv format: status,country,countryCode,city,org)
            URL url = new URL("http://ip-api.com/csv/" + ip + "?fields=status,country,countryCode,city,org");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            conn.setRequestMethod("GET");

            if (conn.getResponseCode() == 200) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                    String line = reader.readLine();
                    if (line != null) {
                        String[] parts = line.split(",");
                        if (parts.length >= 4 && "success".equalsIgnoreCase(parts[0])) {
                            String country = parts[1];
                            String code = parts[2];
                            String city = parts[3];
                            String org = parts.length > 4 ? parts[4] : "ISP";
                            String flag = countryCodeToFlag(code);
                            return new GeoLocation(ip, country, code, city, org, flag);
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.debug("GeoIP lookup failed for IP {}: {}", ip, e.getMessage());
        }

        return new GeoLocation(ip, "Unknown Location", "XX", "Unknown", "Unknown ASN", "🌐");
    }

    private boolean isPrivateOrLocal(String ip) {
        return ip.equals("127.0.0.1") ||
               ip.equals("0:0:0:0:0:0:0:1") ||
               ip.equals("localhost") ||
               ip.startsWith("10.") ||
               ip.startsWith("192.168.") ||
               ip.startsWith("172.16.") ||
               ip.startsWith("172.17.") ||
               ip.startsWith("172.18.") ||
               ip.startsWith("172.19.") ||
               ip.startsWith("172.20.") ||
               ip.startsWith("172.21.") ||
               ip.startsWith("172.22.") ||
               ip.startsWith("172.23.") ||
               ip.startsWith("172.24.") ||
               ip.startsWith("172.25.") ||
               ip.startsWith("172.26.") ||
               ip.startsWith("172.27.") ||
               ip.startsWith("172.28.") ||
               ip.startsWith("172.29.") ||
               ip.startsWith("172.30.") ||
               ip.startsWith("172.31.");
    }

    private String countryCodeToFlag(String code) {
        if (code == null || code.length() != 2) return "🌐";
        int firstChar = Character.codePointAt(code.toUpperCase(), 0) - 0x41 + 0x1F1E6;
        int secondChar = Character.codePointAt(code.toUpperCase(), 1) - 0x41 + 0x1F1E6;
        return new String(Character.toChars(firstChar)) + new String(Character.toChars(secondChar));
    }
}
