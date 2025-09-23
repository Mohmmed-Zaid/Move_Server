package com.moveapp.movebackend.service;

import com.moveapp.movebackend.exception.ResourceNotFoundException;
import com.moveapp.movebackend.model.dto.RoutesDto.CoordinateDto;
import com.moveapp.movebackend.model.dto.RoutesDto.RouteRequest;
import com.moveapp.movebackend.model.dto.RoutesDto.RouteResponse;
import com.moveapp.movebackend.model.entities.Route;
import com.moveapp.movebackend.model.entities.User;
import com.moveapp.movebackend.model.enums.RouteType;
import com.moveapp.movebackend.repository.RouteRepository;
import com.moveapp.movebackend.repository.UserRepository;
import com.moveapp.movebackend.repository.ExternalRoutingService;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class UserRouteServiceImpl implements UserRouteService {

    private final RouteRepository routeRepository;
    private final UserRepository userRepository;
    private final ExternalRoutingService externalRoutingService;
    private final ObjectMapper objectMapper;

    @Override
    @Transactional
    public RouteResponse calculateRoute(String userEmail, RouteRequest request) {
        log.info("Calculating and saving route for user: {}", userEmail);

        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + userEmail));

        try {
            log.info("Calling external routing service with request: {}", request);

            // Calculate route using external service
            Route route = externalRoutingService.calculateRoute(request);

            if (route == null) {
                throw new RuntimeException("External routing service returned null route");
            }

            log.info("External service returned route with distance: {}, duration: {}",
                    route.getDistance(), route.getDuration());

            // Set user and ensure all required fields are set
            route.setUser(user);

            // Ensure isFavorite is set to false by default if null
            if (route.getIsFavorite() == null) {
                route.setIsFavorite(false);
            }

            // Ensure routeType is set
            if (route.getRouteType() == null) {
                route.setRouteType(request.getRouteType() != null ? request.getRouteType() : RouteType.DRIVING);
            }

            // Validate required fields before saving
            validateRoute(route);

            log.info("Saving route to database for user: {}", userEmail);
            Route saved = routeRepository.save(route);
            log.info("Route saved successfully with ID: {}", saved.getId());

            return convertToResponse(saved);

        } catch (Exception e) {
            log.error("Error calculating/saving route for user {}: {}", userEmail, e.getMessage(), e);
            throw new RuntimeException("Failed to calculate and save route: " + e.getMessage(), e);
        }
    }

    private void validateRoute(Route route) {
        if (route.getFromLatitude() == null || route.getFromLongitude() == null) {
            throw new IllegalArgumentException("From coordinates are required");
        }
        if (route.getToLatitude() == null || route.getToLongitude() == null) {
            throw new IllegalArgumentException("To coordinates are required");
        }
        if (route.getDistance() == null || route.getDistance() <= 0) {
            throw new IllegalArgumentException("Valid distance is required");
        }
        if (route.getDuration() == null || route.getDuration() <= 0) {
            throw new IllegalArgumentException("Valid duration is required");
        }
    }

    @Override
    @Transactional(readOnly = true)
    public Page<RouteResponse> getUserRoutes(String userEmail, Pageable pageable) {
        log.info("Fetching routes for user: {} with pageable: {}", userEmail, pageable);

        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + userEmail));

        Page<Route> routes = routeRepository.findByUserOrderByCreatedAtDesc(user, pageable);
        log.info("Found {} routes for user: {}", routes.getTotalElements(), userEmail);

        return routes.map(this::convertToResponse);
    }

    @Override
    @Transactional(readOnly = true)
    public RouteResponse getRoute(Long routeId, String userEmail) {
        log.info("Fetching route {} for user: {}", routeId, userEmail);

        Route route = routeRepository.findByIdAndUserEmail(routeId, userEmail)
                .orElseThrow(() -> new ResourceNotFoundException("Route not found with id " + routeId));

        return convertToResponse(route);
    }

    @Override
    @Transactional
    public RouteResponse toggleFavorite(Long routeId, String userEmail) {
        log.info("Toggling favorite status for route {} by user: {}", routeId, userEmail);

        Route route = routeRepository.findByIdAndUserEmail(routeId, userEmail)
                .orElseThrow(() -> new ResourceNotFoundException("Route not found with id " + routeId));

        // Toggle favorite status
        Boolean currentFavorite = route.getIsFavorite();
        boolean newFavoriteStatus = !Boolean.TRUE.equals(currentFavorite);

        log.info("Changing favorite status from {} to {} for route {}", currentFavorite, newFavoriteStatus, routeId);

        route.setIsFavorite(newFavoriteStatus);
        Route updated = routeRepository.save(route);

        log.info("Successfully updated favorite status for route {} to {}", routeId, newFavoriteStatus);

        return convertToResponse(updated);
    }
    @Override
    @Transactional
    public void deleteRoute(Long routeId, String userEmail) {
        log.info("Deleting route {} for user: {}", routeId, userEmail);

        Route route = routeRepository.findByIdAndUserEmail(routeId, userEmail)
                .orElseThrow(() -> new ResourceNotFoundException("Route not found with id " + routeId));

        routeRepository.delete(route);
        log.info("Successfully deleted route {} for user: {}", routeId, userEmail);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<RouteResponse> getFavoriteRoutes(String userEmail, Pageable pageable) {
        log.info("Fetching favorite routes for user: {}", userEmail);

        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + userEmail));

        Page<Route> favoriteRoutes = routeRepository.findByUserAndIsFavoriteTrueOrderByCreatedAtDesc(user, pageable);
        log.info("Found {} favorite routes for user: {}", favoriteRoutes.getTotalElements(), userEmail);

        return favoriteRoutes.map(this::convertToResponse);
    }

    private RouteResponse convertToResponse(Route route) {
        List<CoordinateDto> coordinates = parseCoordinates(route.getRouteCoordinates());

        return RouteResponse.builder()
                .id(route.getId())
                .fromAddress(route.getFromAddress())
                .fromLatitude(route.getFromLatitude())
                .fromLongitude(route.getFromLongitude())
                .toAddress(route.getToAddress())
                .toLatitude(route.getToLatitude())
                .toLongitude(route.getToLongitude())
                .distance(route.getDistance())
                .duration(route.getDuration())
                .formattedDistance(formatDistance(route.getDistance()))
                .formattedDuration(formatDuration(route.getDuration()))
                .routeType(route.getRouteType())
                .isFavorite(route.getIsFavorite())
                .coordinates(coordinates)
                .routeCoordinates(route.getRouteCoordinates())
                .trafficCondition(route.getTrafficCondition() != null ? route.getTrafficCondition().toString() : null)
                .createdAt(route.getCreatedAt())
                .build();
    }

    private List<CoordinateDto> parseCoordinates(String routeCoordinates) {
        if (routeCoordinates == null || routeCoordinates.trim().isEmpty()) {
            return new ArrayList<>();
        }

        try {
            return objectMapper.readValue(routeCoordinates, new TypeReference<List<CoordinateDto>>() {});
        } catch (Exception e) {
            log.warn("Failed to parse route coordinates: {}", e.getMessage());
            return new ArrayList<>();
        }
    }

    private String formatDistance(Double distanceKm) {
        if (distanceKm == null) return "";
        return distanceKm >= 1
                ? String.format("%.1f km", distanceKm)
                : String.format("%.0f m", distanceKm * 1000);
    }

    private String formatDuration(Double durationMinutes) {
        if (durationMinutes == null) return "";
        int totalMinutes = durationMinutes.intValue();  // Convert Double to int
        int hours = totalMinutes / 60;
        int minutes = totalMinutes % 60;
        if (hours > 0) {
            return String.format("%dh %02dm", hours, minutes);
        }
        return String.format("%dm", minutes);
    }
}