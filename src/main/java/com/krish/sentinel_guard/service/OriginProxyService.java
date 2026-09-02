package com.krish.sentinel_guard.service;

import com.krish.sentinel_guard.waf.filter.CachedBodyHttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Set;

@Service
public class OriginProxyService {

    private static final Logger log = LoggerFactory.getLogger(OriginProxyService.class);

    private static final Set<String> HOP_BY_HOP = Set.of(
            "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
            "te", "trailers", "transfer-encoding", "upgrade", "content-length", "host",
            "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-forwarded-port", "x-real-ip"
    );

    private final HttpClient httpClient = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(60))
            .build();

    public void forward(CachedBodyHttpServletRequest request, HttpServletResponse response, String originUrl)
            throws IOException {
        URI target = buildTargetUri(originUrl, request.getRequestURI(), request.getQueryString());
        byte[] body = request.getCachedBody();
        String method = request.getMethod();

        HttpRequest.BodyPublisher publisher = (body.length == 0 || isBodyless(method))
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofByteArray(body);

        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(target)
                .timeout(Duration.ofSeconds(60))
                .method(method, publisher);

        Enumeration<String> headerNames = request.getHeaderNames();
        if (headerNames != null) {
            while (headerNames.hasMoreElements()) {
                String name = headerNames.nextElement();
                if (name == null || HOP_BY_HOP.contains(name.toLowerCase(Locale.ROOT))) {
                    continue;
                }
                Enumeration<String> values = request.getHeaders(name);
                while (values.hasMoreElements()) {
                    builder.header(name, values.nextElement());
                }
            }
        }

        String clientIp = firstForwardedIp(request);
        builder.header("X-Forwarded-Host", request.getHeader("Host") != null ? request.getHeader("Host") : request.getServerName());
        builder.header("X-Forwarded-Proto", forwardedProto(request));
        builder.header("X-Real-IP", clientIp);
        String existingXff = request.getHeader("X-Forwarded-For");
        builder.header("X-Forwarded-For", existingXff == null || existingXff.isBlank() ? clientIp : existingXff);

        try {
            HttpResponse<InputStream> originResponse = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofInputStream());
            response.setStatus(originResponse.statusCode());
            originResponse.headers().map().forEach((name, values) -> {
                if (name == null || HOP_BY_HOP.contains(name.toLowerCase(Locale.ROOT))) {
                    return;
                }
                for (String value : values) {
                    response.addHeader(name, value);
                }
            });
            try (InputStream in = originResponse.body()) {
                in.transferTo(response.getOutputStream());
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Origin proxy interrupted", e);
        } catch (IOException e) {
            log.warn("Origin unreachable at {}: {}", target, e.getMessage());
            throw e;
        }
    }

    URI buildTargetUri(String originUrl, String requestPath, String queryString) {
        URI origin = URI.create(originUrl);
        String path = (requestPath == null || requestPath.isBlank()) ? "/" : requestPath;
        try {
            return new URI(
                    origin.getScheme(),
                    null,
                    origin.getHost(),
                    origin.getPort(),
                    path,
                    queryString,
                    null
            );
        } catch (Exception e) {
            throw new IllegalArgumentException("Cannot build origin URI from " + originUrl + path, e);
        }
    }

    private static boolean isBodyless(String method) {
        return "GET".equalsIgnoreCase(method)
                || "HEAD".equalsIgnoreCase(method)
                || "OPTIONS".equalsIgnoreCase(method)
                || "TRACE".equalsIgnoreCase(method);
    }

    private static String firstForwardedIp(CachedBodyHttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) {
            return realIp.trim();
        }
        return request.getRemoteAddr() != null ? request.getRemoteAddr() : "unknown";
    }

    private static String forwardedProto(CachedBodyHttpServletRequest request) {
        String proto = request.getHeader("X-Forwarded-Proto");
        if (proto != null && !proto.isBlank()) {
            return proto.split(",")[0].trim();
        }
        return request.isSecure() ? "https" : "http";
    }
}
