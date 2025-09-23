package com.moveapp.movebackend.repository;

import com.moveapp.movebackend.model.entities.User;
import com.moveapp.movebackend.model.entities.UserLocation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserLocationRepository extends JpaRepository<UserLocation, Long> {

    // Method that takes User entity and returns Optional
    Optional<UserLocation> findByUserAndIsActiveTrue(User user);

    // Method that takes User entity and returns List (if you need multiple results)
    List<UserLocation> findAllByUserAndIsActiveTrue(User user);

    // Custom query method that takes user email and returns Optional
    @Query("SELECT ul FROM UserLocation ul WHERE ul.user.email = :userEmail AND ul.isActive = true")
    Optional<UserLocation> findActiveLocationByUserEmail(@Param("userEmail") String userEmail);

    // Custom query method that takes user email and returns List
    @Query("SELECT ul FROM UserLocation ul WHERE ul.user.email = :userEmail AND ul.isActive = true")
    List<UserLocation> findAllActiveLocationsByUserEmail(@Param("userEmail") String userEmail);

    @Query("SELECT ul FROM UserLocation ul WHERE ul.locationSharingEnabled = true AND ul.isActive = true AND ul.updatedAt > :since")
    List<UserLocation> findUsersWithActiveLocationSharing(@Param("since") LocalDateTime since);

    @Query("SELECT ul FROM UserLocation ul WHERE ul.locationSharingEnabled = true AND ul.isActive = true " +
            "AND ul.latitude BETWEEN :minLat AND :maxLat AND ul.longitude BETWEEN :minLon AND :maxLon " +
            "AND ul.user.email != :excludeUserEmail")
    List<UserLocation> findNearbyUsersWithLocationSharing(
            @Param("minLat") Double minLat, @Param("maxLat") Double maxLat,
            @Param("minLon") Double minLon, @Param("maxLon") Double maxLon,
            @Param("excludeUserEmail") String excludeUserEmail);

    void deleteByUserAndIsActiveFalse(User user);
}
