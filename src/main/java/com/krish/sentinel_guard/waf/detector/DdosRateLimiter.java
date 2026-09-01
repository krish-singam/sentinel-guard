package com.krish.sentinel_guard.waf.detector;

import com.krish.sentinel_guard.model.BannedIp;
import com.krish.sentinel_guard.model.ThreatType;
import com.krish.sentinel_guard.repository.BannedIpRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Component
public class DdosRateLimiter {

    private static final Logger log = LoggerFactory.getLogger(DdosRateLimiter.class);

    @Value("${sentinel.waf.rate-limit.requests-per-second:50}")
    private int requestsPerSecond;

    @Value("${sentinel.waf.rate-limit.burst-capacity:100}")
    private int burstCapacity;

    @Value("${sentinel.waf.rate-limit.ip-ban-duration-seconds:300}")
    private int ipBanDurationSeconds;

    private final BannedIpRepository bannedIpRepository;

    // In-memory sliding window bucket per IP: clientIp -> Bucket
    private final Map<String, TokenBucket> buckets = new ConcurrentHashMap<>();

    // In-memory quick lookup for active banned IPs
    private final Map<String, Long> activeBans = new ConcurrentHashMap<>(); // IP -> EpochMilli expiry

    public DdosRateLimiter(BannedIpRepository bannedIpRepository) {
        this.bannedIpRepository = bannedIpRepository;
    }

    public record RateLimitResult(
        boolean allowed,
        boolean isBanned,
        int currentRps,
        int remainingTokens,
        String reason
    ) {}

    public RateLimitResult checkRateLimit(String clientIp) {
        long now = Instant.now().toEpochMilli();

        // 1. Check if IP is actively banned
        Long banExpiry = activeBans.get(clientIp);
        if (banExpiry != null) {
            if (now < banExpiry) {
                return new RateLimitResult(false, true, 0, 0, "IP address is banned in Firewall Jail until " + (banExpiry - now)/1000 + "s");
            } else {
                activeBans.remove(clientIp);
            }
        }

        // 2. Token Bucket evaluation
        TokenBucket bucket = buckets.computeIfAbsent(clientIp, k -> new TokenBucket(burstCapacity, requestsPerSecond));
        boolean consumed = bucket.tryConsume(1);

        if (!consumed) {
            int violations = bucket.incrementViolations();
            if (violations >= 3) {
                // Ban IP
                banIp(clientIp, "Automated DDoS Mitigation: Exceeded rate limit thresholds multiple times", ThreatType.DOS_HTTP_FLOOD, ipBanDurationSeconds);
                return new RateLimitResult(false, true, bucket.getCurrentRps(), 0, "IP banned due to suspected HTTP Flood DDoS attack");
            }
            return new RateLimitResult(false, false, bucket.getCurrentRps(), 0, "Rate limit exceeded (HTTP 429 Too Many Requests)");
        }

        return new RateLimitResult(true, false, bucket.getCurrentRps(), bucket.getAvailableTokens(), "Allowed");
    }

    public synchronized void banIp(String ipAddress, String reason, ThreatType threatType, int durationSeconds) {
        long expiryEpoch = Instant.now().toEpochMilli() + (durationSeconds * 1000L);
        activeBans.put(ipAddress, expiryEpoch);

        try {
            BannedIp bannedIp = bannedIpRepository.findByIpAddress(ipAddress)
                .orElse(new BannedIp(ipAddress, "Unknown", reason, threatType, durationSeconds));
            bannedIp.setViolationCount(bannedIp.getViolationCount() + 1);
            bannedIp.setBannedUntil(LocalDateTime.now().plusSeconds(durationSeconds));
            bannedIp.setActive(true);
            bannedIp.setReason(reason);
            bannedIpRepository.save(bannedIp);
            log.warn("🛡️ IP BANNED: {} for {}s | Reason: {}", ipAddress, durationSeconds, reason);
        } catch (Exception e) {
            log.error("Failed to persist banned IP: {}", ipAddress, e);
        }
    }

    public boolean unbanIp(String ipAddress) {
        activeBans.remove(ipAddress);
        return bannedIpRepository.findByIpAddress(ipAddress).map(banned -> {
            banned.setActive(false);
            bannedIpRepository.save(banned);
            log.info("🔓 IP UNBANNED: {}", ipAddress);
            return true;
        }).orElse(false);
    }

    public boolean isIpBanned(String ipAddress) {
        Long banExpiry = activeBans.get(ipAddress);
        return banExpiry != null && Instant.now().toEpochMilli() < banExpiry;
    }

    public List<BannedIp> getActiveBannedIps() {
        return bannedIpRepository.findByActiveTrue();
    }

    @Scheduled(fixedRate = 60000)
    public void cleanupBucketsAndBans() {
        long now = Instant.now().toEpochMilli();
        // Remove expired bans
        activeBans.entrySet().removeIf(entry -> entry.getValue() <= now);

        // Remove idle token buckets older than 5 minutes
        buckets.entrySet().removeIf(entry -> entry.getValue().isIdle(now, 300000));
    }

    // Token Bucket implementation
    private static class TokenBucket {
        private final int capacity;
        private final double refillRatePerMs;
        private double availableTokens;
        private long lastRefillTimestamp;
        private final AtomicInteger violations = new AtomicInteger(0);
        private final AtomicInteger requestCountInCurrentSecond = new AtomicInteger(0);
        private long currentSecondEpoch;

        public TokenBucket(int capacity, int refillRatePerSecond) {
            this.capacity = capacity;
            this.refillRatePerMs = (double) refillRatePerSecond / 1000.0;
            this.availableTokens = capacity;
            this.lastRefillTimestamp = System.currentTimeMillis();
            this.currentSecondEpoch = System.currentTimeMillis() / 1000;
        }

        public synchronized boolean tryConsume(int tokens) {
            refill();
            long sec = System.currentTimeMillis() / 1000;
            if (sec != currentSecondEpoch) {
                currentSecondEpoch = sec;
                requestCountInCurrentSecond.set(0);
            }
            requestCountInCurrentSecond.incrementAndGet();

            if (availableTokens >= tokens) {
                availableTokens -= tokens;
                return true;
            }
            return false;
        }

        private void refill() {
            long now = System.currentTimeMillis();
            long elapsed = now - lastRefillTimestamp;
            if (elapsed > 0) {
                double tokensToAdd = elapsed * refillRatePerMs;
                availableTokens = Math.min(capacity, availableTokens + tokensToAdd);
                lastRefillTimestamp = now;
            }
        }

        public int incrementViolations() {
            return violations.incrementAndGet();
        }

        public synchronized int getAvailableTokens() {
            refill();
            return (int) availableTokens;
        }

        public int getCurrentRps() {
            return requestCountInCurrentSecond.get();
        }

        public synchronized boolean isIdle(long now, long idleThresholdMs) {
            return (now - lastRefillTimestamp) > idleThresholdMs;
        }
    }
}
