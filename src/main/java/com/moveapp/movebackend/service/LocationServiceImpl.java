package com.moveapp.movebackend.service;

import com.moveapp.movebackend.model.dto.LocationDto.*;
import com.moveapp.movebackend.model.entities.Location;
import com.moveapp.movebackend.model.entities.User;
import com.moveapp.movebackend.model.entities.UserLocation;
import com.moveapp.movebackend.model.enums.LocationCategory;
import com.moveapp.movebackend.repository.LocationRepository;
import com.moveapp.movebackend.repository.UserLocationRepository;
import com.moveapp.movebackend.repository.UserRepository;
import com.moveapp.movebackend.service.external.GeoCodingService;
import com.moveapp.movebackend.utils.GeoUtils;
import com.moveapp.movebackend.utils.ValidationUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class LocationServiceImpl {

    private final LocationRepository locationRepository;
    private final UserLocationRepository userLocationRepository;
    private final UserRepository userRepository;
    private final GeoCodingService geoCodingService;
    private final SimpMessagingTemplate messagingTemplate;

    public Page<LocationDto> searchLocation(String query, Pageable pageable) {
        Page<Location> localResult = locationRepository.searchByAddress(query, pageable);

        if (localResult.getContent().size() < 5) {
            List<Location> externalResult = geoCodingService.searchLocations(query);

            for (Location location : externalResult) {
                if (locationRepository.findByPlaceId(location.getPlaceId()).isEmpty()) {
                    locationRepository.save(location);
                }
            }
        }

        return locationRepository.searchByAddress(query, pageable)
                .map(this::convertToDto);
    }

    public List<LocationDto> getPopularLocations() {
        List<Location> popularLocations = locationRepository.findByIsPopularTrueOrderBySearchCountDesc();
        return popularLocations.stream()
                .map(this::convertToDto)
                .collect(Collectors.toList());
    }

    public List<LocationDto> getLocationsByCategory(LocationCategory category) {
        List<Location> locations = locationRepository.findByCategory(category);
        return locations.stream()
                .map(this::convertToDto)
                .collect(Collectors.toList());
    }

    public List<LocationDto> getNearbyLocations(double latitude, double longitude, double radiusKm) {
        if (!ValidationUtils.isValidCoordinate(latitude, longitude)) {
            return List.of();
        }

        // Calculate bounding box for the search radius
        double latOffset = radiusKm / 111.0; // Approximate: 1 degree lat = 111 km
        double lonOffset = radiusKm / (111.0 * Math.cos(Math.toRadians(latitude)));

        double minLat = latitude - latOffset;
        double maxLat = latitude + latOffset;
        double minLon = longitude - lonOffset;
        double maxLon = longitude + lonOffset;

        List<Location> nearbyLocations = locationRepository
                .findByCoordinateBounds(minLat, maxLat, minLon, maxLon);

        // Filter by actual distance and sort by distance
        return nearbyLocations.stream()
                .filter(location -> {
                    double distance = GeoUtils.calculateHaversineDistance(
                            latitude, longitude,
                            location.getLatitude(), location.getLongitude());
                    return distance <= radiusKm;
                })
                .sorted((l1, l2) -> {
                    double d1 = GeoUtils.calculateHaversineDistance(latitude, longitude,
                            l1.getLatitude(), l1.getLongitude());
                    double d2 = GeoUtils.calculateHaversineDistance(latitude, longitude,
                            l2.getLatitude(), l2.getLongitude());
                    return Double.compare(d1, d2);
                })
                .map(this::convertToDto)
                .collect(Collectors.toList());
    }

    public LocationDto reverseGeocode(double latitude, double longitude) {
        if (!ValidationUtils.isValidCoordinate(latitude, longitude)) {
            return null;
        }

        try {
            return geoCodingService.reverseGeocode(latitude, longitude);
        } catch (Exception e) {
            log.error("Error reverse geocoding coordinates {}, {}: {}",
                    latitude, longitude, e.getMessage());
            return null;
        }
    }

    // Live Location Features
    public LiveLocationResponse updateLiveLocation(String userEmail, LiveLocationUpdateRequest request) {
        try {
            User user = userRepository.findByEmail(userEmail.toLowerCase().trim())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            if (!ValidationUtils.isValidCoordinate(request.getLatitude(), request.getLongitude())) {
                throw new IllegalArgumentException("Invalid coordinates");
            }

            // Check if there's an existing location record
            Optional<UserLocation> existingLocation = userLocationRepository.findByUserAndIsActiveTrue(user);

            UserLocation userLocation;
            if (existingLocation.isPresent()) {
                userLocation = existingLocation.get();

                // Validate reasonable location update
                if (!ValidationUtils.isReasonableLocationUpdate(
                        userLocation.getLatitude(), userLocation.getLongitude(),
                        request.getLatitude(), request.getLongitude(),
                        java.time.Duration.between(userLocation.getUpdatedAt(), LocalDateTime.now()).toMillis())) {
                    log.warn("Unreasonable location update for user: {}", userEmail);
                }

                userLocation.setLatitude(request.getLatitude());
                userLocation.setLongitude(request.getLongitude());
                userLocation.setAccuracy(request.getAccuracy());
                userLocation.setSpeed(request.getSpeed());
                userLocation.setBearing(request.getBearing());
                userLocation.setAltitude(request.getAltitude());

            } else {
                userLocation = UserLocation.builder()
                        .user(user)
                        .latitude(request.getLatitude())
                        .longitude(request.getLongitude())
                        .accuracy(request.getAccuracy())
                        .speed(request.getSpeed())
                        .bearing(request.getBearing())
                        .altitude(request.getAltitude())
                        .isActive(true)
                        .locationSharingEnabled(false)
                        .build();
            }

            userLocation = userLocationRepository.save(userLocation);

            // Reverse geocode to get address
            LocationDto locationInfo = reverseGeocode(request.getLatitude(), request.getLongitude());
            String address = locationInfo != null ? locationInfo.getAddress() : "Unknown location";

            // Send real-time update if location sharing is enabled
            if (userLocation.getLocationSharingEnabled()) {
                sendLocationUpdate(user, userLocation, address);
            }

            log.info("Live location updated for user: {} at {}, {}", userEmail,
                    request.getLatitude(), request.getLongitude());

            return LiveLocationResponse.builder()
                    .success(true)
                    .message("Location updated successfully")
                    .latitude(userLocation.getLatitude())
                    .longitude(userLocation.getLongitude())
                    .accuracy(userLocation.getAccuracy())
                    .address(address)
                    .timestamp(userLocation.getUpdatedAt())
                    .build();

        } catch (Exception e) {
            log.error("Error updating live location for user: {}", userEmail, e);
            return LiveLocationResponse.builder()
                    .success(false)
                    .message("Failed to update location: " + e.getMessage())
                    .build();
        }
    }

    public LiveLocationResponse getCurrentLocation(String userEmail) {
        try {
            User user = userRepository.findByEmail(userEmail.toLowerCase().trim())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            Optional<UserLocation> userLocation = userLocationRepository.findByUserAndIsActiveTrue(user);

            if (userLocation.isEmpty()) {
                return LiveLocationResponse.builder()
                        .success(false)
                        .message("No location data available")
                        .build();
            }

            UserLocation location = userLocation.get();

            // Check if location is stale (older than 10 minutes)
            if (location.getUpdatedAt().isBefore(LocalDateTime.now().minusMinutes(10))) {
                return LiveLocationResponse.builder()
                        .success(false)
                        .message("Location data is stale")
                        .build();
            }

            LocationDto locationInfo = reverseGeocode(location.getLatitude(), location.getLongitude());
            String address = locationInfo != null ? locationInfo.getAddress() : "Unknown location";

            return LiveLocationResponse.builder()
                    .success(true)
                    .message("Location retrieved successfully")
                    .latitude(location.getLatitude())
                    .longitude(location.getLongitude())
                    .accuracy(location.getAccuracy())
                    .speed(location.getSpeed())
                    .bearing(location.getBearing())
                    .altitude(location.getAltitude())
                    .address(address)
                    .timestamp(location.getUpdatedAt())
                    .build();

        } catch (Exception e) {
            log.error("Error getting current location for user: {}", userEmail, e);
            return LiveLocationResponse.builder()
                    .success(false)
                    .message("Failed to get location: " + e.getMessage())
                    .build();
        }
    }

    public LiveLocationResponse toggleLocationSharing(String userEmail, boolean enabled) {
        try {
            User user = userRepository.findByEmail(userEmail.toLowerCase().trim())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            Optional<UserLocation> userLocation = userLocationRepository.findByUserAndIsActiveTrue(user);

            if (userLocation.isPresent()) {
                UserLocation location = userLocation.get();
                location.setLocationSharingEnabled(enabled);
                userLocationRepository.save(location);

                return LiveLocationResponse.builder()
                        .success(true)
                        .message("Location sharing " + (enabled ? "enabled" : "disabled"))
                        .build();
            } else {
                return LiveLocationResponse.builder()
                        .success(false)
                        .message("No location data available to share")
                        .build();
            }

        } catch (Exception e) {
            log.error("Error toggling location sharing for user: {}", userEmail, e);
            return LiveLocationResponse.builder()
                    .success(false)
                    .message("Failed to toggle location sharing: " + e.getMessage())
                    .build();
        }
    }

    public void stopLocationSharing(String userEmail) {
        try {
            User user = userRepository.findByEmail(userEmail.toLowerCase().trim())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            userLocationRepository.findByUserAndIsActiveTrue(user)
                    .ifPresent(location -> {
                        location.setIsActive(false);
                        location.setLocationSharingEnabled(false);
                        userLocationRepository.save(location);
                        log.info("Location sharing stopped for user: {}", userEmail);
                    });

        } catch (Exception e) {
            log.error("Error stopping location sharing for user: {}", userEmail, e);
        }
    }

    private void sendLocationUpdate(User user, UserLocation location, String address) {
        try {
            LiveLocationUpdate update = LiveLocationUpdate.builder()
                    .userId(user.getId())
                    .userEmail(user.getEmail())
                    .userName(user.getName())
                    .latitude(location.getLatitude())
                    .longitude(location.getLongitude())
                    .accuracy(location.getAccuracy())
                    .speed(location.getSpeed())
                    .bearing(location.getBearing())
                    .address(address)
                    .timestamp(location.getUpdatedAt())
                    .build();

            // Send to user's personal channel
            messagingTemplate.convertAndSendToUser(
                    user.getEmail(),
                    "/queue/location",
                    update
            );

            // Send to shared location channel if needed
            messagingTemplate.convertAndSend("/topic/locations/" + user.getId(), update);

        } catch (Exception e) {
            log.error("Failed to send location update: {}", e.getMessage());
        }
    }

    private LocationDto convertToDto(Location location) {
        return LocationDto.builder()
                .id(location.getId())
                .address(location.getAddress())
                .latitude(location.getLatitude())
                .longitude(location.getLongitude())
                .placeId(location.getPlaceId())
                .category(location.getCategory())
                .isPopular(location.getIsPopular())
                .build();
    }
}