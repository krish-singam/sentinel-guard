package com.krish.sentinel_guard.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Public Traffic Gateway Endpoint.
 * All incoming requests to /api/traffic/** or /gateway/** pass through WafTrafficInspectionFilter.
 * If the request contains an attack vector, WAF returns HTTP 403 Forbidden automatically.
 * If clean, this controller returns HTTP 200 OK with packet telemetry.
 */
@RestController
@RequestMapping({"/api/traffic", "/gateway"})
public class TrafficGatewayController {

    @GetMapping({"", "/stream", "/check", "/ping"})
    public ResponseEntity<Map<String, Object>> handleGetTraffic(
            HttpServletRequest request,
            @RequestParam(required = false) Map<String, String> allParams) {

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("status", 200);
        resp.put("wafStatus", "PASSED_CLEAN");
        resp.put("message", "Traffic passed WAF deep inspection successfully.");
        resp.put("remoteAddr", request.getRemoteAddr());
        resp.put("host", request.getHeader("Host"));
        resp.put("userAgent", request.getHeader("User-Agent"));
        resp.put("paramsEvaluated", allParams != null ? allParams.size() : 0);
        resp.put("timestamp", LocalDateTime.now().toString());

        return ResponseEntity.ok(resp);
    }

    @PostMapping({"", "/submit", "/inspect"})
    public ResponseEntity<Map<String, Object>> handlePostTraffic(
            HttpServletRequest request,
            @RequestBody(required = false) String rawBody,
            @RequestParam(required = false) Map<String, String> allParams) {

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("status", 200);
        resp.put("wafStatus", "PASSED_CLEAN");
        resp.put("message", "Payload passed WAF deep inspection successfully.");
        resp.put("remoteAddr", request.getRemoteAddr());
        resp.put("host", request.getHeader("Host"));
        resp.put("payloadSize", rawBody != null ? rawBody.length() : 0);
        resp.put("timestamp", LocalDateTime.now().toString());

        return ResponseEntity.ok(resp);
    }
}
