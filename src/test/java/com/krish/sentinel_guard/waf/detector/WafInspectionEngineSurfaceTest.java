package com.krish.sentinel_guard.waf.detector;

import com.krish.sentinel_guard.waf.payload.PayloadNormalizer;
import com.krish.sentinel_guard.waf.payload.PayloadSurface;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class WafInspectionEngineSurfaceTest {

    private final PayloadNormalizer normalizer = new PayloadNormalizer();
    private final SqlInjectionDetector sql = new SqlInjectionDetector();
    private final XssDetector xss = new XssDetector();
    private final RceDetector rce = new RceDetector();

    @Test
    void detectsSqlInjectionInNestedJsonBody() {
        List<PayloadSurface> surfaces = normalizer.normalize(
                "/api/users",
                null,
                Map.of("Content-Type", "application/json"),
                "{\"fullName\":\"Alex\",\"bio\":\"1' OR 1=1--\"}".getBytes(StandardCharsets.UTF_8),
                "application/json",
                StandardCharsets.UTF_8
        );

        assertThat(surfaces)
                .anyMatch(s -> sql.detect(s.value()).detected());
    }

    @Test
    void detectsXssInCustomHeader() {
        List<PayloadSurface> surfaces = normalizer.normalize(
                "/api/users",
                null,
                Map.of("X-Custom-Ref", "<script>alert(1)</script>"),
                new byte[0],
                null,
                StandardCharsets.UTF_8
        );

        assertThat(surfaces)
                .anyMatch(s -> xss.detect(s.value()).detected());
    }

    @Test
    void detectsRceInQueryString() {
        List<PayloadSurface> surfaces = normalizer.normalize(
                "/api/users",
                "keyword=;cat /etc/passwd",
                Map.of(),
                new byte[0],
                null,
                StandardCharsets.UTF_8
        );

        assertThat(surfaces)
                .anyMatch(s -> rce.detect(s.value()).detected());
    }
}
