package com.moveapp.movebackend.repository;

import com.moveapp.movebackend.model.entities.Route;
import com.moveapp.movebackend.model.entities.User;
import com.moveapp.movebackend.model.enums.RouteType;
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
public interface RouteRepository extends JpaRepository<Route, Long> {

    Page<Route> findByUserOrderByCreatedAtDesc(User user, Pageable pageable);

    // Added missing method used in RouteServiceImpl
    Page<Route> findByUserAndIsFavoriteTrueOrderByCreatedAtDesc(User user, Pageable pageable);

    // Added missing method used in RouteServiceImpl
    Optional<Route> findByIdAndUserEmail(Long id, String userEmail);

    List<Route> findByUserAndRouteTypeOrderByCreatedAtDesc(User user, RouteType routeType);

    @Query("SELECT r FROM Route r WHERE r.user = :user AND " +
            "(LOWER(r.fromAddress) LIKE LOWER(CONCAT('%', :query, '%')) OR " +
            "LOWER(r.toAddress) LIKE LOWER(CONCAT('%', :query, '%')))")
    Page<Route> findByUserAndAddressContaining(@Param("user") User user,
                                               @Param("query") String query,
                                               Pageable pageable);

    @Query("SELECT r FROM Route r WHERE r.user = :user AND r.createdAt >= :since")
    List<Route> findByUserAndCreatedAtAfter(@Param("user") User user, @Param("since") LocalDateTime since);

    Long countByUser(User user);

    @Query("SELECT AVG(r.distance) FROM Route r WHERE r.user = :user")
    Double findAverageDistanceByUser(@Param("user") User user);

    @Query("SELECT SUM(r.distance) FROM Route r WHERE r.user = :user")
    Double findTotalDistanceByUser(@Param("user") User user);
}