package com.krish.sentinel_guard.repository;

import com.krish.sentinel_guard.model.MonitoredDomain;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface MonitoredDomainRepository extends JpaRepository<MonitoredDomain, Long> {
    Optional<MonitoredDomain> findByDomainNameIgnoreCase(String domainName);
    boolean existsByDomainNameIgnoreCase(String domainName);
}
