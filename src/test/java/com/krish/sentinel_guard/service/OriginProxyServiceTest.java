package com.krish.sentinel_guard.service;

import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;

class OriginProxyServiceTest {

    private final OriginProxyService proxy = new OriginProxyService();

    @Test
    void buildsOriginUriWithPathAndQuery() {
        URI uri = proxy.buildTargetUri("http://127.0.0.1:8085", "/api/users", "keyword=alex");
        assertThat(uri.toString()).isEqualTo("http://127.0.0.1:8085/api/users?keyword=alex");
    }
}
