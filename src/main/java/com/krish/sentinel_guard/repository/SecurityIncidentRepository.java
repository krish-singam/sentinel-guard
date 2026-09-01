package com.krish.sentinel_guard.repository;

import com.krish.sentinel_guard.model.ActionTaken;
import com.krish.sentinel_guard.model.SecurityIncident;
import com.krish.sentinel_guard.model.ThreatType;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface SecurityIncidentRepository extends JpaRepository<SecurityIncident, Long> {

    List<SecurityIncident> findByOrderByTimestampDesc(Pageable pageable);

    List<SecurityIncident> findByDomainNameIgnoreCaseOrderByTimestampDesc(String domainName, Pageable pageable);

    List<SecurityIncident> findByThreatTypeOrderByTimestampDesc(ThreatType threatType, Pageable pageable);

    List<SecurityIncident> findByTimestampAfterOrderByTimestampDesc(LocalDateTime timestamp, Pageable pageable);

    List<SecurityIncident> findByTimestampBetweenOrderByTimestampDesc(LocalDateTime start, LocalDateTime end, Pageable pageable);

    long countByBlockedTrue();

    long countByThreatType(ThreatType threatType);

    long countByTimestampAfter(LocalDateTime timestamp);

    long countByTimestampBefore(LocalDateTime cutoff);

    long countByTimestampBetween(LocalDateTime start, LocalDateTime end);

    @Modifying
    @Transactional
    @Query("DELETE FROM SecurityIncident s WHERE s.timestamp < :cutoff")
    int deleteByTimestampBefore(@Param("cutoff") LocalDateTime cutoff);

    @Query("SELECT s.threatType, COUNT(s) FROM SecurityIncident s GROUP BY s.threatType")
    List<Object[]> countIncidentsByThreatType();

    @Query("SELECT s.clientCountry, COUNT(s) FROM SecurityIncident s WHERE s.clientCountry IS NOT NULL GROUP BY s.clientCountry ORDER BY COUNT(s) DESC")
    List<Object[]> countIncidentsByCountry(Pageable pageable);

    @Query("SELECT s.actionTaken, COUNT(s) FROM SecurityIncident s GROUP BY s.actionTaken")
    List<Object[]> countIncidentsByAction();
}
