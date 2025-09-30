package com.moveapp.movebackend.controller;

import com.moveapp.movebackend.model.dto.LocationDto.*;
import com.moveapp.movebackend.model.enums.LocationCategory;
import com.moveapp.movebackend.service.LocationServiceImpl;
import jakarta.validation.Valid;
import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/locations")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = {"http://localhost:5173", "move-ui-three.vercel.app"})
public class LocationController {

    private final LocationServiceImpl locationService;

    // ===== SEARCH ENDPOINTS =====

    @GetMapping("/search")
    public ResponseEntity<ApiResponse<LocationSearchResponse>> searchLocation(
            @RequestParam @NotBlank(message = "Query parameter is required") String query,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        try {
            long startTime = System.currentTimeMillis();

            Pageable pageable = PageRequest.of(page, size);
            Page<LocationDto> locationPage = locationService.searchLocation(query, pageable);

            long searchTime = System.currentTimeMillis() - startTime;

            LocationSearchResponse response = LocationSearchResponse.builder()
                    .results(locationPage.getContent())
                    .totalResult((int) locationPage.getTotalElements())
                    .page(page)
                    .size(size)
                    .hasNext(locationPage.hasNext())
                    .hasPrevious(locationPage.hasPrevious())
                    .query(query)
                    .searchTimeMs(searchTime)
                    .build();

            return ResponseEntity.ok(ApiResponse.<LocationSearchResponse>builder()
                    .success(true)
                    .message("Location search completed successfully")
                    .data(response)
                    .timestamp(System.currentTimeMillis())
                    .build());

        } catch (Exception e) {
            log.error("Error searching locations for query: {}", query, e);
            return ResponseEntity.status(500)
                    .body(ApiResponse.<LocationSearchResponse>builder()
                            .success(false)
                            .message("Error searching locations")
                            .error("LOCATION_SEARCH_ERROR")
                            .timestamp(System.currentTimeMillis())
                            .build());
        }
    }

    @GetMapping("/popular")
    public ResponseEntity<ApiResponse<List<LocationDto>>> getPopularLocations() {
        try {
            List<LocationDto> popularLocations = locationService.getPopularLocations();

            return ResponseEntity.ok(ApiResponse.<List<LocationDto>>builder()
                    .success(true)
                    .message("Popular locations retrieved successfully")
                    .data(popularLocations)
                    .timestamp(System.currentTimeMillis())
                    .build());

        } catch (Exception e) {
            log.error("Error getting popular locations", e);
            return ResponseEntity.status(500)
                    .body(ApiResponse.<List<LocationDto>>builder()
                            .success(false)
                            .message("Error retrieving popular locations")
                            .error("POPULAR_LOCATIONS_ERROR")
                            .timestamp(System.currentTimeMillis())
                            .build());
        }
    }

    @GetMapping("/category/{category}")
    public ResponseEntity<ApiResponse<List<LocationDto>>> getLocationsByCategory(
            @PathVariable LocationCategory category) {
        try {
            List<LocationDto> locations = locationService.getLocationsByCategory(category);

            return ResponseEntity.ok(ApiResponse.<List<LocationDto>>builder()
                    .success(true)
                    .message("Locations by category retrieved successfully")
                    .data(locations)
                    .timestamp(System.currentTimeMillis())
                    .build());

        } catch (Exception e) {
            log.error("Error getting locations by category: {}", category, e);
            return ResponseEntity.status(500)
                    .body(ApiResponse.<List<LocationDto>>builder()
                            .success(false)
                            .message("Error retrieving locations by category")
                            .error("CATEGORY_LOCATIONS_ERROR")
                            .timestamp(System.currentTimeMillis())
                            .build());
        }
    }

    @GetMapping("/nearby")
    public ResponseEntity<ApiResponse<List<LocationDto>>> getNearbyLocations(
            @RequestParam @DecimalMin(value = "-90.0", message = "Latitude must be between -90 and 90")
            @DecimalMax(value = "90.0", message = "Latitude must be between -90 and 90")
            Double latitude,
            @RequestParam @DecimalMin(value = "-180.0", message = "Longitude must be between -180 and 180")
            @DecimalMax(value = "180.0", message = "Longitude must be between -180 and 180")
            Double longitude,
            @RequestParam(defaultValue = "5.0") @Min(value = 1, message = "Radius must be at least 1 km")
            Double radius) {

        try {
            List<LocationDto> nearbyLocations = locationService.getNearbyLocations(latitude, longitude, radius);

            return ResponseEntity.ok(ApiResponse.<List<LocationDto>>builder()
                    .success(true)
                    .message("Nearby locations retrieved successfully")
                    .data(nearbyLocations)
                    .timestamp(System.currentTimeMillis())
                    .build());

        } catch (Exception e) {
            log.error("Error getting nearby locations for coordinates: {}, {}", latitude, longitude, e);
            return ResponseEntity.status(500)
                    .body(ApiResponse.<List<LocationDto>>builder()
                            .success(false)
                            .message("Error retrieving nearby locations")
                            .error("NEARBY_LOCATIONS_ERROR")
                            .timestamp(System.currentTimeMillis())
                            .build());
        }
    }

    @GetMapping("/reverse")
    public ResponseEntity<ApiResponse<LocationDto>> reverseGeocode(
            @RequestParam @DecimalMin(value = "-90.0", message = "Latitude must be between -90 and 90")
            @DecimalMax(value = "90.0", message = "Latitude must be between -90 and 90")
            Double latitude,
            @RequestParam @DecimalMin(value = "-180.0", message = "Longitude must be between -180 and 180")
            @DecimalMax(value = "180.0", message = "Longitude must be between -180 and 180")
            Double longitude) {

        try {
            LocationDto location = locationService.reverseGeocode(latitude, longitude);

            if (location != null) {
                return ResponseEntity.ok(ApiResponse.<LocationDto>builder()
                        .success(true)
                        .message("Reverse geocoding successful")
                        .data(location)
                        .timestamp(System.currentTimeMillis())
                        .build());
            } else {
                return ResponseEntity.ok(ApiResponse.<LocationDto>builder()
                        .success(false)
                        .message("No location found for the given coordinates")
                        .error("LOCATION_NOT_FOUND")
                        .timestamp(System.currentTimeMillis())
                        .build());
            }

        } catch (Exception e) {
            log.error("Error in reverse geocoding for coordinates: {}, {}", latitude, longitude, e);
            return ResponseEntity.status(500)
                    .body(ApiResponse.<LocationDto>builder()
                            .success(false)
                            .message("Error in reverse geocoding")
                            .error("REVERSE_GEOCODING_ERROR")
                            .timestamp(System.currentTimeMillis())
                            .build());
        }
    }

    // ===== LIVE LOCATION ENDPOINTS =====

    @PostMapping("/live/update")
    public ResponseEntity<ApiResponse<LiveLocationResponse>> updateLiveLocation(
            @Valid @RequestBody LiveLocationUpdateRequest request,
            Authentication authentication) {

        try {
            log.info("Live location update for user: {}", authentication.getName());
            LiveLocationResponse response = locationService.updateLiveLocation(authentication.getName(), request);

            return ResponseEntity.ok(ApiResponse.<LiveLocationResponse>builder()
                    .success(true)
                    .message("Live location updated successfully")
                    .data(response)
                    .timestamp(System.currentTimeMillis())
                    .build());

        } catch (Exception e) {
            log.error("Error updating live location for user: {}", authentication.getName(), e);
            return ResponseEntity.badRequest()
                    .body(ApiResponse.<LiveLocationResponse>builder()
                            .success(false)
                            .message("Failed to update location: " + e.getMessage())
                            .error("LIVE_LOCATION_UPDATE_ERROR")
                            .timestamp(System.currentTimeMillis())
                            .build());
        }
    }

    @GetMapping("/live/current")
    public ResponseEntity<ApiResponse<LiveLocationResponse>> getCurrentLocation(Authentication authentication) {
        try {
            log.info("Getting current location for user: {}", authentication.getName());
            LiveLocationResponse response = locationService.getCurrentLocation(authentication.getName());

            return ResponseEntity.ok(ApiResponse.<LiveLocationResponse>builder()
                    .success(true)
                    .message("Current location retrieved successfully")
                    .data(response)
                    .timestamp(System.currentTimeMillis())
                    .build());

        } catch (Exception e) {
            log.error("Error getting current location for user: {}", authentication.getName(), e);
            return ResponseEntity.badRequest()
                    .body(ApiResponse.<LiveLocationResponse>builder()
                            .success(false)
                            .message("Failed to get current location: " + e.getMessage())
                            .error("CURRENT_LOCATION_ERROR")
                            .timestamp(System.currentTimeMillis())
                            .build());
        }
    }

    @PostMapping("/live/share")
    public ResponseEntity<ApiResponse<LiveLocationResponse>> toggleLocationSharing(
            @Valid @RequestBody LocationShareRequest request,
            Authentication authentication) {

        try {
            log.info("Toggling location sharing for user: {} to: {}",
                    authentication.getName(), request.getEnabled());

            LiveLocationResponse response = locationService.toggleLocationSharing(
                    authentication.getName(), request.getEnabled());

            return ResponseEntity.ok(ApiResponse.<LiveLocationResponse>builder()
                    .success(true)
                    .message("Location sharing toggled successfully")
                    .data(response)
                    .timestamp(System.currentTimeMillis())
                    .build());

        } catch (Exception e) {
            log.error("Error toggling location sharing for user: {}", authentication.getName(), e);
            return ResponseEntity.badRequest()
                    .body(ApiResponse.<LiveLocationResponse>builder()
                            .success(false)
                            .message("Failed to toggle location sharing: " + e.getMessage())
                            .error("LOCATION_SHARING_ERROR")
                            .timestamp(System.currentTimeMillis())
                            .build());
        }
    }

    @PostMapping("/live/stop")
    public ResponseEntity<ApiResponse<Map<String, Object>>> stopLocationSharing(Authentication authentication) {
        try {
            log.info("Stopping location sharing for user: {}", authentication.getName());
            locationService.stopLocationSharing(authentication.getName());

            Map<String, Object> result = new HashMap<>();
            result.put("stopped", true);
            result.put("user", authentication.getName());

            return ResponseEntity.ok(ApiResponse.<Map<String, Object>>builder()
                    .success(true)
                    .message("Location sharing stopped successfully")
                    .data(result)
                    .timestamp(System.currentTimeMillis())
                    .build());

        } catch (Exception e) {
            log.error("Error stopping location sharing for user: {}", authentication.getName(), e);
            return ResponseEntity.status(500)
                    .body(ApiResponse.<Map<String, Object>>builder()
                            .success(false)
                            .message("Error stopping location sharing")
                            .error("STOP_LOCATION_SHARING_ERROR")
                            .timestamp(System.currentTimeMillis())
                            .build());
        }
    }

    @GetMapping("/live/nearby-users")
    public ResponseEntity<ApiResponse<List<NearbyUsersResponse>>> getNearbyUsers(
            @RequestParam(defaultValue = "5.0") @Min(value = 1, message = "Radius must be at least 1 km")
            Double radius,
            Authentication authentication) {

        try {
            log.info("Getting nearby users for user: {} within {} km",
                    authentication.getName(), radius);

            // Mock implementation - implement in service when ready
            List<NearbyUsersResponse> nearbyUsers = List.of();

            return ResponseEntity.ok(ApiResponse.<List<NearbyUsersResponse>>builder()
                    .success(true)
                    .message("Nearby users retrieved successfully")
                    .data(nearbyUsers)
                    .timestamp(System.currentTimeMillis())
                    .build());

        } catch (Exception e) {
            log.error("Error getting nearby users for user: {}", authentication.getName(), e);
            return ResponseEntity.status(500)
                    .body(ApiResponse.<List<NearbyUsersResponse>>builder()
                            .success(false)
                            .message("Error retrieving nearby users")
                            .error("NEARBY_USERS_ERROR")
                            .timestamp(System.currentTimeMillis())
                            .build());
        }
    }

    // ===== INNER CLASSES =====

    @Data
    public static class ApiResponse<T> {
        private boolean success;
        private String message;
        private T data;
        private String error;
        private long timestamp;

        public static <T> ApiResponseBuilder<T> builder() {
            return new ApiResponseBuilder<T>();
        }
    }

    public static class ApiResponseBuilder<T> {
        private boolean success;
        private String message;
        private T data;
        private String error;
        private long timestamp;

        public ApiResponseBuilder<T> success(boolean success) {
            this.success = success;
            return this;
        }

        public ApiResponseBuilder<T> message(String message) {
            this.message = message;
            return this;
        }

        public ApiResponseBuilder<T> data(T data) {
            this.data = data;
            return this;
        }

        public ApiResponseBuilder<T> error(String error) {
            this.error = error;
            return this;
        }

        public ApiResponseBuilder<T> timestamp(long timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public ApiResponse<T> build() {
            ApiResponse<T> response = new ApiResponse<>();
            response.success = this.success;
            response.message = this.message;
            response.data = this.data;
            response.error = this.error;
            response.timestamp = this.timestamp;
            return response;
        }
    }
}