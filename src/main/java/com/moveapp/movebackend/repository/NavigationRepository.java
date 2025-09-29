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

    // Find active session by user email and route ID
    @Query("SELECT n FROM NavigationSession n WHERE n.user.email = :email AND n.route.id = :routeId AND n.isActive = true")
    Optional<NavigationSession> findActiveSessionByUserAndRoute(@Param("email") String email, @Param("routeId") Long routeId);

    // Find all active sessions by user email
    @Query("SELECT n FROM NavigationSession n WHERE n.user.email = :email AND n.isActive = true")
    List<NavigationSession> findActiveSessionsByUserEmail(@Param("email") String email);

    // Find completed sessions by user with pagination
    @Query("SELECT n FROM NavigationSession n WHERE n.user = :user AND n.isActive = false ORDER BY n.startTime DESC")
    Page<NavigationSession> findCompletedSessionsByUser(@Param("user") User user, Pageable pageable);

    // Count user navigations since a specific date
    @Query("SELECT COUNT(n) FROM NavigationSession n WHERE n.user = :user AND n.startTime >= :since")
    Long countUserNavigationsSince(@Param("user") User user, @Param("since") LocalDateTime since);

    // Find stale active sessions (inactive for too long)
    @Query("SELECT n FROM NavigationSession n WHERE n.isActive = true AND n.updatedAt < :cutoffTime")
    List<NavigationSession> findStaleActiveSessions(@Param("cutoffTime") LocalDateTime cutoffTime);

    // Find by ID and user
    @Query("SELECT n FROM NavigationSession n WHERE n.id = :id AND n.user = :user")
    Optional<NavigationSession> findByIdAndUser(@Param("id") Long id, @Param("user") User user);

    // Count active sessions by user
    @Query("SELECT COUNT(n) FROM NavigationSession n WHERE n.user = :user AND n.isActive = true")
    Long countActiveByUser(@Param("user") User user);

    // Find latest session by user
    Optional<NavigationSession> findFirstByUserOrderByStartTimeDesc(User user);

    // Find sessions by user ordered by start time
    List<NavigationSession> findByUserOrderByStartTimeDesc(User user);
}

//package com.moveapp.movebackend.repository;
//
//import com.moveapp.movebackend.model.entities.NavigationSession;
//import com.moveapp.movebackend.model.entities.User;
//import org.springframework.data.domain.Page;
//import org.springframework.data.domain.Pageable;
//import org.springframework.data.jpa.repository.JpaRepository;
//import org.springframework.data.jpa.repository.Query;
//import org.springframework.data.repository.query.Param;
//import org.springframework.stereotype.Repository;
//
//import java.time.LocalDateTime;
//import java.util.List;
//import java.util.Optional;
//
//@Repository
//public interface NavigationRepository extends JpaRepository<NavigationSession, Long> {
//
//    Optional<NavigationSession> findByIdAndUser(Long id, User user);
//
//    List<NavigationSession> findByUserAndIsActiveTrue(User user);
//
//    @Query("SELECT ns FROM NavigationSession ns WHERE ns.user.email = :userEmail AND ns.isActive = true")
//    List<NavigationSession> findActiveSessionsByUserEmail(@Param("userEmail") String userEmail);
//
//    @Query("SELECT ns FROM NavigationSession ns WHERE ns.user = :user AND ns.isActive = false ORDER BY ns.endTime DESC")
//    Page<NavigationSession> findCompletedSessionsByUser(@Param("user") User user, Pageable pageable);
//
//    @Query("SELECT ns FROM NavigationSession ns WHERE ns.user.email = :userEmail AND ns.route.id = :routeId AND ns.isActive = true")
//    Optional<NavigationSession> findActiveSessionByUserAndRoute(@Param("userEmail") String userEmail, @Param("routeId") Long routeId);
//
//    @Query("SELECT COUNT(ns) FROM NavigationSession ns WHERE ns.user = :user AND ns.startTime >= :startDate")
//    Long countUserNavigationsSince(@Param("user") User user, @Param("startDate") LocalDateTime startDate);
//
//    @Query("SELECT ns FROM NavigationSession ns WHERE ns.isActive = true AND ns.updatedAt < :cutoffTime")
//    List<NavigationSession> findStaleActiveSessions(@Param("cutoffTime") LocalDateTime cutoffTime);
//}