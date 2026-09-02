package com.krish.sentinel_guard.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Service
public class WafPublicIdentityService {

    private final String publicIp;
    private final String publicIpv6;
    private final boolean treatLoopbackAsWaf;

    public WafPublicIdentityService(
            @Value("${sentinel.waf.public-ip:140.245.250.50}") String publicIp,
            @Value("${sentinel.waf.public-ipv6:}") String publicIpv6,
            @Value("${sentinel.waf.treat-loopback-as-waf:true}") boolean treatLoopbackAsWaf) {
        this.publicIp = publicIp;
        this.publicIpv6 = publicIpv6;
        this.treatLoopbackAsWaf = treatLoopbackAsWaf;
    }

    public boolean pointsToWaf(List<String> ipv4List, List<String> ipv6List) {
        Set<String> ours = ourAddresses();
        if (ipv4List != null) {
            for (String ip : ipv4List) {
                if (ip != null && ours.contains(ip.trim().toLowerCase(Locale.ROOT))) {
                    return true;
                }
            }
        }
        if (ipv6List != null) {
            for (String ip : ipv6List) {
                if (ip != null && ours.contains(normalizeIpv6(ip))) {
                    return true;
                }
            }
        }
        return false;
    }

    public Set<String> ourAddresses() {
        Set<String> ours = new HashSet<>();
        if (publicIp != null && !publicIp.isBlank()) {
            ours.add(publicIp.trim().toLowerCase(Locale.ROOT));
        }
        if (publicIpv6 != null && !publicIpv6.isBlank()) {
            ours.add(normalizeIpv6(publicIpv6));
        }
        if (treatLoopbackAsWaf) {
            ours.add("127.0.0.1");
            ours.add("::1");
            ours.add("0:0:0:0:0:0:0:1");
        }
        return ours;
    }

    private static String normalizeIpv6(String ip) {
        return ip.trim().toLowerCase(Locale.ROOT);
    }
}
