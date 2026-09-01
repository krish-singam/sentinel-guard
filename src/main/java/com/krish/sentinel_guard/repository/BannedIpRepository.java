package com.krish.sentinel_guard.repository;

import com.krish.sentinel_guard.model.BannedIp;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface BannedIpRepository extends JpaRepository<BannedIp, Long> {
    Optional<BannedIp> findByIpAddress(String ipAddress);
    Optional<BannedIp> findByIpAddressAndActiveTrue(String ipAddress);
    List<BannedIp> findByActiveTrue();
    List<BannedIp> findByActiveTrueAndBannedUntilAfter(LocalDateTime now);
    boolean existsByIpAddressAndActiveTrue(String ipAddress);
}
