package com.moveapp.movebackend.repository;

import com.moveapp.movebackend.model.entities.NavigationSession;
import com.moveapp.movebackend.model.entities.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface NavigationRepository extends JpaRepository<NavigationSession, Long> {

    Optional<NavigationSession> findByIdAndUser(Long id, User user);

    List<NavigationSession> findByUserAndIsActiveTrue(User user);

    @Query("SELECT ns FROM NavigationSession ns WHERE ns.user.email = :userEmail AND ns.isActive = true")
    List<NavigationSession> findActiveSessionsByUserEmail(@Param("userEmail") String userEmail);

    @Query("SELECT ns FROM NavigationSession ns WHERE ns.user = :user AND ns.isActive = false ORDER BY ns.endTime DESC")
    Page<NavigationSession> findCompletedSessionsByUser(@Param("user") User user, Pageable pageable);

    @Query("SELECT ns FROM NavigationSession ns WHERE ns.user.email = :userEmail AND ns.route.id = :routeId AND ns.isActive = true")
    Optional<NavigationSession> findActiveSessionByUserAndRoute(@Param("userEmail") String userEmail, @Param("routeId") Long routeId);

    @Query("SELECT COUNT(ns) FROM NavigationSession ns WHERE ns.user = :user AND ns.startTime >= :startDate")
    Long countUserNavigationsSince(@Param("user") User user, @Param("startDate") LocalDateTime startDate);

    @Query("SELECT ns FROM NavigationSession ns WHERE ns.isActive = true AND ns.updatedAt < :cutoffTime")
    List<NavigationSession> findStaleActiveSessions(@Param("cutoffTime") LocalDateTime cutoffTime);
}