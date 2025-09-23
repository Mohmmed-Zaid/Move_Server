package com.moveapp.movebackend.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.moveapp.movebackend.exception.ResourceNotFoundException;
import com.moveapp.movebackend.model.dto.NavigationDto.*;
import com.moveapp.movebackend.model.entities.NavigationSession;
import com.moveapp.movebackend.model.entities.Route;
import com.moveapp.movebackend.model.entities.User;
import com.moveapp.movebackend.repository.NavigationRepository;
import com.moveapp.movebackend.repository.RouteRepository;
import com.moveapp.movebackend.repository.UserRepository;
import com.moveapp.movebackend.utils.GeoUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class NavigationServiceImpl {

    private final NavigationRepository navigationRepository;
    private final RouteRepository routeRepository;
    private final UserRepository userRepository;
    // Removed RoutingService dependency - you need to implement this or remove references
    private final SimpMessagingTemplate messagingTemplate;
    private final ObjectMapper objectMapper;

    // In-memory cache for active sessions to improve performance
    private final Map<Long, NavigationSession> activeSessionsCache = new ConcurrentHashMap<>();

    // Speed limits and warnings
    private static final double CITY_SPEED_LIMIT = 50.0; // km/h
    private static final double HIGHWAY_SPEED_LIMIT = 120.0; // km/h
    private static final double OFF_ROUTE_THRESHOLD = 0.1; // 100 meters
    private static final int SESSION_TIMEOUT_MINUTES = 30;

    public NavigationResponse startNavigation(String userEmail, StartNavigationRequest request) {
        User user = findUserByEmail(userEmail);
        Route route = findRouteById(request.getRouteId());

        // Check for existing active session on this route
        Optional<NavigationSession> existingSession = navigationRepository
                .findActiveSessionByUserAndRoute(userEmail, request.getRouteId());

        if (existingSession.isPresent()) {
            log.warn("User {} already has active navigation session for route {}", userEmail, request.getRouteId());
            return convertToResponse(existingSession.get());
        }

        // Calculate initial remaining distance and time
        double remainingDistance = GeoUtils.calculateHaversineDistance(
                request.getStartLatitude(), request.getStartLongitude(),
                route.getToLatitude(), route.getToLongitude()
        );

        // FIXED: Convert Double to int safely
        int remainingTime = estimateRemainingTime(remainingDistance,
                route.getDuration(), route.getDistance());

        NavigationSession session = NavigationSession.builder()
                .user(user)
                .route(route)
                .currentLatitude(request.getStartLatitude())
                .currentLongitude(request.getStartLongitude())
                .remainingDistance(remainingDistance)
                .remainingTime(remainingTime)
                .isActive(true)
                .isOffRoute(false)
                .build();

        NavigationSession savedSession = navigationRepository.save(session);
        activeSessionsCache.put(savedSession.getId(), savedSession);

        NavigationResponse response = convertToResponse(savedSession);

        // Send real-time update
        sendRealTimeUpdate(savedSession, "NAVIGATION_STARTED", "Navigation started successfully");

        log.info("Started navigation session {} for user {} on route {}",
                savedSession.getId(), userEmail, request.getRouteId());

        return response;
    }

    public NavigationResponse updateLocation(String userEmail, LocationUpdateRequest request) {
        NavigationSession session = findActiveSessionByIdAndUser(request.getSessionId(), userEmail);

        // Update current location
        session.setCurrentLatitude(request.getCurrentLatitude());
        session.setCurrentLongitude(request.getCurrentLongitude());

        Route route = session.getRoute();

        // Check if user is off route
        boolean wasOffRoute = Boolean.TRUE.equals(session.getIsOffRoute());
        boolean isCurrentlyOffRoute = isOffRoute(request.getCurrentLatitude(),
                request.getCurrentLongitude(), route);

        session.setIsOffRoute(isCurrentlyOffRoute);

        // Calculate remaining distance and time
        double remainingDistance = GeoUtils.calculateHaversineDistance(
                request.getCurrentLatitude(), request.getCurrentLongitude(),
                route.getToLatitude(), route.getToLongitude()
        );

        session.setRemainingDistance(remainingDistance);
        // FIXED: Convert Double to int safely
        session.setRemainingTime(estimateRemainingTime(remainingDistance,
                route.getDuration(), route.getDistance()));

        // Handle speed monitoring
        String speedWarning = null;
        if (request.getCurrentSpeed() != null) {
            speedWarning = checkSpeedLimit(request.getCurrentSpeed());
        }

        NavigationSession updatedSession = navigationRepository.save(session);
        activeSessionsCache.put(updatedSession.getId(), updatedSession);

        NavigationResponse response = convertToResponse(updatedSession);
        if (speedWarning != null) {
            response.setSpeedWarning(speedWarning);
        }

        // Send real-time updates for significant events
        if (!wasOffRoute && isCurrentlyOffRoute) {
            sendRealTimeUpdate(updatedSession, "OFF_ROUTE", "You are off the planned route");
            // Trigger route recalculation
            recalculateRoute(updatedSession);
        } else if (wasOffRoute && !isCurrentlyOffRoute) {
            sendRealTimeUpdate(updatedSession, "BACK_ON_ROUTE", "Back on planned route");
        }

        if (speedWarning != null) {
            sendRealTimeUpdate(updatedSession, "SPEED_WARNING", speedWarning);
        }

        // Check if destination reached (within 50 meters)
        if (remainingDistance < 0.05) {
            return completeNavigation(updatedSession.getId(), userEmail);
        }

        // Regular location update
        sendRealTimeUpdate(updatedSession, "LOCATION_UPDATE", null);

        return response;
    }

    public NavigationResponse completeNavigation(Long sessionId, String userEmail) {
        NavigationSession session = findActiveSessionByIdAndUser(sessionId, userEmail);

        session.setIsActive(false);
        session.setEndTime(LocalDateTime.now());
        session.setRemainingDistance(0.0);
        session.setRemainingTime(0);

        NavigationSession completedSession = navigationRepository.save(session);
        activeSessionsCache.remove(sessionId);

        NavigationResponse response = convertToResponse(completedSession);

        sendRealTimeUpdate(completedSession, "ARRIVAL", "Destination reached!");

        log.info("Completed navigation session {} for user {}", sessionId, userEmail);

        return response;
    }

    public void stopNavigation(Long sessionId, String userEmail) {
        NavigationSession session = findActiveSessionByIdAndUser(sessionId, userEmail);

        session.setIsActive(false);
        session.setEndTime(LocalDateTime.now());

        navigationRepository.save(session);
        activeSessionsCache.remove(sessionId);

        sendRealTimeUpdate(session, "NAVIGATION_STOPPED", "Navigation stopped");

        log.info("Stopped navigation session {} for user {}", sessionId, userEmail);
    }

    public NavigationStatusResponse getNavigationStatus(String userEmail) {
        List<NavigationSession> activeSessions = navigationRepository.findActiveSessionsByUserEmail(userEmail);

        NavigationStatusResponse response = NavigationStatusResponse.builder()
                .hasActiveNavigation(!activeSessions.isEmpty())
                .build();

        if (!activeSessions.isEmpty()) {
            // Return the most recent active session
            NavigationSession latestSession = activeSessions.stream()
                    .max((s1, s2) -> s1.getStartTime().compareTo(s2.getStartTime()))
                    .orElse(null);

            if (latestSession != null) {
                response.setActiveSession(convertToResponse(latestSession));
            }
        }

        return response;
    }

    public Page<NavigationResponse> getNavigationHistory(String userEmail, Pageable pageable) {
        User user = findUserByEmail(userEmail);
        return navigationRepository.findCompletedSessionsByUser(user, pageable)
                .map(this::convertToResponse);
    }

    public NavigationStatsResponse getNavigationStats(String userEmail) {
        User user = findUserByEmail(userEmail);
        LocalDateTime weekStart = LocalDateTime.now().minusWeeks(1);
        LocalDateTime monthStart = LocalDateTime.now().minusMonths(1);

        // Fixed: Count only user's navigations, not total
        Long totalNavigations = navigationRepository.countUserNavigationsSince(user, LocalDateTime.of(1970, 1, 1, 0, 0));
        Long weekNavigations = navigationRepository.countUserNavigationsSince(user, weekStart);
        Long monthNavigations = navigationRepository.countUserNavigationsSince(user, monthStart);

        // Calculate totals from completed sessions
        List<NavigationSession> completedSessions = navigationRepository
                .findCompletedSessionsByUser(user, Pageable.unpaged()).getContent();

        double totalDistance = completedSessions.stream()
                .filter(s -> s.getRoute() != null)
                .mapToDouble(s -> s.getRoute().getDistance())
                .sum();

        int totalTime = completedSessions.stream()
                .filter(s -> s.getStartTime() != null && s.getEndTime() != null)
                .mapToInt(s -> (int) ChronoUnit.MINUTES.between(s.getStartTime(), s.getEndTime()))
                .sum();

        double averageSpeed = totalTime > 0 ? (totalDistance / (totalTime / 60.0)) : 0.0;

        return NavigationStatsResponse.builder()
                .totalNavigations(totalNavigations)
                .totalNavigationsThisWeek(weekNavigations)
                .totalNavigationsThisMonth(monthNavigations)
                .totalDistanceNavigated(totalDistance)
                .totalTimeNavigated(totalTime)
                .averageSpeed(averageSpeed)
                .build();
    }

    // Private helper methods
    private NavigationSession findActiveSessionByIdAndUser(Long sessionId, String userEmail) {
        // Check cache first
        NavigationSession cachedSession = activeSessionsCache.get(sessionId);
        if (cachedSession != null && cachedSession.getUser().getEmail().equals(userEmail)) {
            return cachedSession;
        }

        User user = findUserByEmail(userEmail);
        return navigationRepository.findByIdAndUser(sessionId, user)
                .filter(session -> Boolean.TRUE.equals(session.getIsActive()))
                .orElseThrow(() -> new ResourceNotFoundException("Active navigation session not found with id " + sessionId));
    }

    private User findUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + email));
    }

    private Route findRouteById(Long routeId) {
        return routeRepository.findById(routeId)
                .orElseThrow(() -> new ResourceNotFoundException("Route not found with id " + routeId));
    }

    private boolean isOffRoute(double currentLat, double currentLon, Route route) {
        try {
            if (route.getRouteCoordinates() == null || route.getRouteCoordinates().isEmpty()) {
                return false;
            }

            // Parse route coordinates JSON
            List<Map<String, Double>> coordinates = objectMapper.readValue(
                    route.getRouteCoordinates(),
                    new TypeReference<List<Map<String, Double>>>() {}
            );

            // Find minimum distance to route path
            double minDistance = coordinates.stream()
                    .mapToDouble(coord -> GeoUtils.calculateHaversineDistance(
                            currentLat, currentLon,
                            coord.get("lat"), coord.get("lon")
                    ))
                    .min()
                    .orElse(Double.MAX_VALUE);

            return minDistance > OFF_ROUTE_THRESHOLD;
        } catch (Exception e) {
            log.error("Error checking if off route: {}", e.getMessage());
            return false;
        }
    }

    // FIXED: Method accepts Double and safely converts to int
    private int estimateRemainingTime(double remainingDistance, Double originalDurationMinutes, double originalDistance) {
        if (originalDistance == 0 || originalDurationMinutes == null) return 0;
        double ratio = remainingDistance / originalDistance;
        return (int) Math.ceil(originalDurationMinutes.doubleValue() * ratio);
    }

    private String checkSpeedLimit(double currentSpeed) {
        if (currentSpeed > HIGHWAY_SPEED_LIMIT) {
            return "Speed warning: Exceeding highway limit (" + HIGHWAY_SPEED_LIMIT + " km/h)";
        } else if (currentSpeed > CITY_SPEED_LIMIT * 1.2) { // 20% over city limit
            return "Speed warning: Exceeding city limit (" + CITY_SPEED_LIMIT + " km/h)";
        }
        return null;
    }

    private void recalculateRoute(NavigationSession session) {
        try {
            // This would typically call your external routing service
            log.info("Triggering route recalculation for session {}", session.getId());
            // Implementation would depend on your RoutingService - removed dependency for now
            // You can add this back when you implement the RoutingService
        } catch (Exception e) {
            log.error("Failed to recalculate route for session {}: {}", session.getId(), e.getMessage());
        }
    }

    private void sendRealTimeUpdate(NavigationSession session, String updateType, String message) {
        try {
            RealTimeUpdate update = RealTimeUpdate.builder()
                    .sessionId(session.getId())
                    .updateType(updateType)
                    .navigationData(convertToResponse(session))
                    .message(message)
                    .timestamp(LocalDateTime.now())
                    .build();

            messagingTemplate.convertAndSendToUser(
                    session.getUser().getEmail(),
                    "/queue/navigation",
                    update
            );
        } catch (Exception e) {
            log.error("Failed to send real-time update: {}", e.getMessage());
        }
    }

    private NavigationResponse convertToResponse(NavigationSession session) {
        Route route = session.getRoute();

        return NavigationResponse.builder()
                .sessionId(session.getId())
                .routeId(route.getId())
                .routeName(route.getFromAddress() + " → " + route.getToAddress())
                .currentLatitude(session.getCurrentLatitude())
                .currentLongitude(session.getCurrentLongitude())
                .remainingDistance(session.getRemainingDistance())
                .remainingTime(session.getRemainingTime())
                .formattedDistance(formatDistance(session.getRemainingDistance()))
                .formattedTime(formatDuration(session.getRemainingTime()))
                .isActive(session.getIsActive())
                .isOffRoute(session.getIsOffRoute())
                .startTime(session.getStartTime())
                .lastUpdated(session.getUpdatedAt())
                .routeInfo(RouteInfo.builder()
                        .fromAddress(route.getFromAddress())
                        .toAddress(route.getToAddress())
                        .totalDistance(route.getDistance())
                        // FIXED: Safely convert Double to int with null check
                        .totalDuration(route.getDuration() != null ? route.getDuration().intValue() : 0)
                        .routeType(route.getRouteType().name())
                        .build())
                .build();
    }

    private String formatDistance(Double distanceKm) {
        if (distanceKm == null) return "";
        return distanceKm >= 1
                ? String.format("%.1f km", distanceKm)
                : String.format("%.0f m", distanceKm * 1000);
    }

    private String formatDuration(Integer durationMinutes) {
        if (durationMinutes == null) return "";
        int hours = durationMinutes / 60;
        int minutes = durationMinutes % 60;
        if (hours > 0) {
            return String.format("%dh %02dm", hours, minutes);
        }
        return String.format("%dm", minutes);
    }

    // Scheduled task to clean up stale sessions
    @Scheduled(fixedRate = 300000) // Every 5 minutes
    public void cleanupStaleSessions() {
        LocalDateTime cutoffTime = LocalDateTime.now().minusMinutes(SESSION_TIMEOUT_MINUTES);
        List<NavigationSession> staleSessions = navigationRepository.findStaleActiveSessions(cutoffTime);

        staleSessions.forEach(session -> {
            session.setIsActive(false);
            session.setEndTime(LocalDateTime.now());
            activeSessionsCache.remove(session.getId());
            log.warn("Cleaned up stale navigation session {}", session.getId());
        });

        if (!staleSessions.isEmpty()) {
            navigationRepository.saveAll(staleSessions);
        }
    }
}