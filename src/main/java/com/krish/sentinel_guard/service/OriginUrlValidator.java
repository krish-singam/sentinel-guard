package com.krish.sentinel_guard.service;

import java.net.URI;
import java.util.Locale;

/**
 * Restricts origin backends to http(s) and blocks cloud metadata endpoints.
 * Loopback and private LAN addresses are allowed so local/Docker origins work.
 */
public final class OriginUrlValidator {

    private OriginUrlValidator() {}

    public static String sanitize(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String trimmed = raw.trim();
        URI uri;
        try {
            uri = URI.create(trimmed);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid origin URL");
        }
        String scheme = uri.getScheme();
        if (scheme == null
                || (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme))) {
            throw new IllegalArgumentException("Origin URL must use http or https");
        }
        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("Origin URL must include a host");
        }
        if (isBlockedMetadataHost(host)) {
            throw new IllegalArgumentException("Origin URL host is not allowed");
        }

        StringBuilder out = new StringBuilder();
        out.append(scheme.toLowerCase(Locale.ROOT)).append("://").append(host.toLowerCase(Locale.ROOT));
        if (uri.getPort() != -1) {
            out.append(':').append(uri.getPort());
        }
        String path = uri.getPath();
        if (path != null && !path.isBlank() && !"/".equals(path)) {
            if (path.endsWith("/")) {
                path = path.substring(0, path.length() - 1);
            }
            out.append(path);
        }
        return out.toString();
    }

    static boolean isBlockedMetadataHost(String host) {
        String h = host.toLowerCase(Locale.ROOT);
        return "169.254.169.254".equals(h)
                || "metadata.google.internal".equals(h)
                || h.endsWith(".metadata.google.internal")
                || "fd00:ec2::254".equals(h);
    }
}
