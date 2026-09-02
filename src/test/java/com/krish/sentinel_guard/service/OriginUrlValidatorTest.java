package com.krish.sentinel_guard.service;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OriginUrlValidatorTest {

    @Test
    void acceptsLocalHttpOrigin() {
        assertThat(OriginUrlValidator.sanitize("http://127.0.0.1:8085"))
                .isEqualTo("http://127.0.0.1:8085");
    }

    @Test
    void rejectsFileScheme() {
        assertThatThrownBy(() -> OriginUrlValidator.sanitize("file:///etc/passwd"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsCloudMetadataHost() {
        assertThatThrownBy(() -> OriginUrlValidator.sanitize("http://169.254.169.254/latest/meta-data/"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not allowed");
    }
}

class WafPublicIdentityServiceTest {

    @Test
    void matchesSentinelGuardPublicARecord() {
        WafPublicIdentityService service = new WafPublicIdentityService("140.245.250.50", "", true);
        assertThat(service.pointsToWaf(List.of("140.245.250.50"), List.of())).isTrue();
        assertThat(service.pointsToWaf(List.of("1.2.3.4"), List.of())).isFalse();
    }
}
