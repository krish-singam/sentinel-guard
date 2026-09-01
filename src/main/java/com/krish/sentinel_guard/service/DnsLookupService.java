package com.krish.sentinel_guard.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;

import java.net.InetAddress;
import java.util.*;

@Service
public class DnsLookupService {

    private static final Logger log = LoggerFactory.getLogger(DnsLookupService.class);

    public record DnsRecordItem(String type, String value, int ttl, int priority) {}

    public record DnsInspectionResult(
        String domain,
        String primaryIp,
        List<String> ipv4List,
        List<String> ipv6List,
        List<DnsRecordItem> allRecords,
        long resolutionTimeMs,
        boolean reachable
    ) {}

    public DnsInspectionResult inspectDomain(String domain) {
        long start = System.currentTimeMillis();
        String cleanDomain = sanitizeDomain(domain);

        List<String> ipv4List = new ArrayList<>();
        List<String> ipv6List = new ArrayList<>();
        List<DnsRecordItem> allRecords = new ArrayList<>();
        String primaryIp = "Unknown";
        boolean reachable = false;

        try {
            // 1. Resolve A records (IPv4)
            Lookup aLookup = new Lookup(cleanDomain, Type.A);
            Record[] aRecords = aLookup.run();
            if (aRecords != null) {
                for (Record r : aRecords) {
                    if (r instanceof ARecord ar) {
                        String ip = ar.getAddress().getHostAddress();
                        ipv4List.add(ip);
                        allRecords.add(new DnsRecordItem("A", ip, (int) ar.getTTL(), 0));
                    }
                }
                if (!ipv4List.isEmpty()) {
                    primaryIp = ipv4List.get(0);
                    reachable = true;
                }
            }

            // Fallback native lookup if dnsjava didn't find A records
            if (ipv4List.isEmpty()) {
                try {
                    InetAddress[] addrs = InetAddress.getAllByName(cleanDomain);
                    for (InetAddress a : addrs) {
                        ipv4List.add(a.getHostAddress());
                    }
                    if (!ipv4List.isEmpty()) {
                        primaryIp = ipv4List.get(0);
                        reachable = true;
                    }
                } catch (Exception ignored) {}
            }

            // 2. Resolve AAAA records (IPv6)
            Lookup aaaaLookup = new Lookup(cleanDomain, Type.AAAA);
            Record[] aaaaRecords = aaaaLookup.run();
            if (aaaaRecords != null) {
                for (Record r : aaaaRecords) {
                    if (r instanceof AAAARecord ar) {
                        String ip = ar.getAddress().getHostAddress();
                        ipv6List.add(ip);
                        allRecords.add(new DnsRecordItem("AAAA", ip, (int) ar.getTTL(), 0));
                    }
                }
            }

            // 3. Resolve MX records (Mail)
            Lookup mxLookup = new Lookup(cleanDomain, Type.MX);
            Record[] mxRecords = mxLookup.run();
            if (mxRecords != null) {
                for (Record r : mxRecords) {
                    if (r instanceof MXRecord mx) {
                        allRecords.add(new DnsRecordItem("MX", mx.getTarget().toString(true), (int) mx.getTTL(), mx.getPriority()));
                    }
                }
            }

            // 4. Resolve TXT records (SPF, verification)
            Lookup txtLookup = new Lookup(cleanDomain, Type.TXT);
            Record[] txtRecords = txtLookup.run();
            if (txtRecords != null) {
                for (Record r : txtRecords) {
                    if (r instanceof TXTRecord txt) {
                        String val = String.join("", (List<String>) txt.getStrings());
                        allRecords.add(new DnsRecordItem("TXT", val, (int) txt.getTTL(), 0));
                    }
                }
            }

            // 5. Resolve NS records (Name servers)
            Lookup nsLookup = new Lookup(cleanDomain, Type.NS);
            Record[] nsRecords = nsLookup.run();
            if (nsRecords != null) {
                for (Record r : nsRecords) {
                    if (r instanceof NSRecord ns) {
                        allRecords.add(new DnsRecordItem("NS", ns.getTarget().toString(true), (int) ns.getTTL(), 0));
                    }
                }
            }

            // 6. Resolve CNAME records
            Lookup cnameLookup = new Lookup(cleanDomain, Type.CNAME);
            Record[] cnameRecords = cnameLookup.run();
            if (cnameRecords != null) {
                for (Record r : cnameRecords) {
                    if (r instanceof CNAMERecord cn) {
                        allRecords.add(new DnsRecordItem("CNAME", cn.getTarget().toString(true), (int) cn.getTTL(), 0));
                    }
                }
            }

        } catch (Exception e) {
            log.error("DNS lookup error for domain: {}", cleanDomain, e);
        }

        long elapsed = System.currentTimeMillis() - start;
        return new DnsInspectionResult(cleanDomain, primaryIp, ipv4List, ipv6List, allRecords, elapsed, reachable);
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
