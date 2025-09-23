package com.moveapp.movebackend.repository;

import com.moveapp.movebackend.model.entities.Location;
import com.moveapp.movebackend.model.enums.LocationCategory;
import org.springframework.data.domain.Page;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
@Repository
public interface LocationRepository extends JpaRepository<Location, Long> {

    // Find a location by its Google Place ID (to avoid duplicates)
    Optional<Location> findByPlaceId(String placeId);

    // Search locations by part of the address (case-insensitive) with pagination
    @Query("SELECT l FROM Location l WHERE LOWER(l.address) LIKE LOWER(CONCAT('%', :query, '%'))")
    Page<Location> searchByAddress(@Param("query") String query, Pageable pageable);

    // Get all popular locations ordered by search count (most searched first)
    List<Location> findByIsPopularTrueOrderBySearchCountDesc();


    // Get all locations of a given category (e.g., RESTAURANT, PARK, etc.)
    List<Location> findByCategory(LocationCategory category);

    // Find locations within a latitude-longitude rectangle (map bounding box search)
    @Query("SELECT l FROM Location l WHERE l.latitude BETWEEN :minLat AND :maxLat AND l.longitude BETWEEN :minLon AND :maxLon")
    List<Location> findByCoordinateBounds(@Param("minLat") Double minLat, @Param("maxLat") Double maxLat,
                                          @Param("minLon") Double minLon, @Param("maxLon") Double maxLon);
}
