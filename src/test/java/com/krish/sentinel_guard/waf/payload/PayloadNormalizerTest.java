package com.krish.sentinel_guard.waf.payload;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class PayloadNormalizerTest {

    private final PayloadNormalizer normalizer = new PayloadNormalizer();

    @Test
    void extractsNestedJsonSqlInjectionField() {
        String json = "{\"fullName\":\"Alex\",\"bio\":\"1' OR 1=1--\"}";
        List<PayloadSurface> surfaces = normalizer.normalize(
                "/api/users",
                null,
                Map.of("Content-Type", "application/json"),
                json.getBytes(StandardCharsets.UTF_8),
                "application/json",
                StandardCharsets.UTF_8
        );

        assertThat(surfaces)
                .anyMatch(s -> s.location().contains("bio") && s.value().contains("OR 1=1"));
    }

    @Test
    void extractsFormXssField() {
        List<PayloadSurface> surfaces = normalizer.normalize(
                "/login",
                null,
                Map.of(),
                "comment=<script>alert(1)</script>".getBytes(StandardCharsets.UTF_8),
                "application/x-www-form-urlencoded",
                StandardCharsets.UTF_8
        );

        assertThat(surfaces)
                .anyMatch(s -> s.location().contains("comment") && s.value().contains("<script>"));
    }

    @Test
    void extractsMultipartTextPart() {
        String body = """
                --abc123\r
                Content-Disposition: form-data; name="fullName"\r
                \r
                ;cat /etc/passwd\r
                --abc123--\r
                """;
        List<PayloadSurface> surfaces = normalizer.normalize(
                "/api/users",
                null,
                Map.of(),
                body.getBytes(StandardCharsets.UTF_8),
                "multipart/form-data; boundary=abc123",
                StandardCharsets.UTF_8
        );

        assertThat(surfaces)
                .anyMatch(s -> s.location().contains("fullName") && s.value().contains("/etc/passwd"));
    }

    @Test
    void extractsQueryPathTraversal() {
        List<PayloadSurface> surfaces = normalizer.normalize(
                "/files",
                "path=../../etc/passwd",
                Map.of(),
                new byte[0],
                null,
                StandardCharsets.UTF_8
        );

        assertThat(surfaces)
                .anyMatch(s -> s.value().contains("../../etc/passwd"));
    }
}
