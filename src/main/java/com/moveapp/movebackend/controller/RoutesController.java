package com.moveapp.movebackend.controller;

import com.moveapp.movebackend.model.dto.RoutesDto.RouteRequest;
import com.moveapp.movebackend.model.dto.RoutesDto.RouteResponse;
import com.moveapp.movebackend.model.dto.ApiResponse;
import com.moveapp.movebackend.service.UserRouteService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/routes")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(
        origins = {
                "http://localhost:5173",
                "http://localhost:3000",
                "https://move-ui-three.vercel.app"
        },
        allowedHeaders = "*",
        allowCredentials = "true",
        methods = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE, RequestMethod.OPTIONS}
)
public class RoutesController {

    private final RestTemplate restTemplate;
    private final UserRouteService userRouteService;

    @Value("${move.external.osrm.routing-url:https://router.project-osrm.org}")
    private String osrmUrl;

    @PostMapping("/calculate")
    public ResponseEntity<ApiResponse<Map<String, Object>>> calculateRoute(@RequestBody Map<String, Object> routeRequest) {
        try {
            log.info("Calculating route for request: {}", routeRequest);

            Map<String, Object> from = (Map<String, Object>) routeRequest.get("from");
            Map<String, Object> to = (Map<String, Object>) routeRequest.get("to");

            if (from == null || to == null) {
                return ResponseEntity.badRequest()
                        .body(ApiResponse.error("Both 'from' and 'to' locations are required", "MISSING_LOCATIONS"));
            }

            Double fromLat = getDoubleValue(from.get("lat"));
            Double fromLng = getDoubleValue(from.get("lng"));
            Double toLat = getDoubleValue(to.get("lat"));
            Double toLng = getDoubleValue(to.get("lng"));

            if (fromLat == null || fromLng == null || toLat == null || toLng == null) {
                return ResponseEntity.badRequest()
                        .body(ApiResponse.error("Invalid coordinates provided", "INVALID_COORDINATES"));
            }

            String routeUrl = String.format(
                    "%s/route/v1/driving/%s,%s;%s,%s?overview=full&geometries=geojson&steps=true",
                    osrmUrl, fromLng, fromLat, toLng, toLat
            );

            try {
                ResponseEntity<Map> osrmResponse = restTemplate.getForEntity(routeUrl, Map.class);
                Map<String, Object> osrmData = osrmResponse.getBody();

                if (osrmData != null && "Ok".equals(osrmData.get("code"))) {
                    List<Map<String, Object>> routes = (List<Map<String, Object>>) osrmData.get("routes");
                    if (!routes.isEmpty()) {
                        Map<String, Object> route = routes.get(0);
                        Map<String, Object> geometry = (Map<String, Object>) route.get("geometry");
                        List<List<Double>> coordinates = (List<List<Double>>) geometry.get("coordinates");

                        List<Map<String, Double>> formattedCoordinates = new ArrayList<>();
                        for (List<Double> coord : coordinates) {
                            Map<String, Double> point = new HashMap<>();
                            point.put("lat", coord.get(1));
                            point.put("lng", coord.get(0));
                            formattedCoordinates.add(point);
                        }

                        Map<String, Object> response = new HashMap<>();
                        response.put("distance", route.get("distance"));
                        response.put("duration", route.get("duration"));
                        response.put("coordinates", formattedCoordinates);
                        response.put("from", from);
                        response.put("to", to);
                        response.put("timestamp", LocalDateTime.now().toString());
                        response.put("routeType", routeRequest.getOrDefault("routeType", "FASTEST"));
                        response.put("transportMode", routeRequest.getOrDefault("transportMode", "DRIVING"));

                        log.info("Route calculated successfully");
                        return ResponseEntity.ok(ApiResponse.success(response, "Route calculated successfully"));
                    }
                }

                return ResponseEntity.badRequest()
                        .body(ApiResponse.error("No route found between the specified locations", "NO_ROUTE_FOUND"));

            } catch (Exception osrmError) {
                log.error("OSRM request failed", osrmError);
                return ResponseEntity.status(503)
                        .body(ApiResponse.error("Route calculation service temporarily unavailable", "SERVICE_UNAVAILABLE"));
            }

        } catch (Exception e) {
            log.error("Error calculating route", e);
            return ResponseEntity.status(500)
                    .body(ApiResponse.error("Internal server error during route calculation", "INTERNAL_SERVER_ERROR"));
        }
    }

    @PostMapping("/save")
    public ResponseEntity<ApiResponse<RouteResponse>> saveRoute(
            @Validated @RequestBody RouteRequest routeRequest,
            Authentication authentication) {
        try {
            log.info("Calculating and saving route for user: {}", authentication.getName());
            RouteResponse response = userRouteService.calculateRoute(authentication.getName(), routeRequest);
            return ResponseEntity.ok(ApiResponse.success(response, "Route calculated and saved successfully"));
        } catch (Exception e) {
            log.error("Error calculating and saving route", e);
            return ResponseEntity.status(500)
                    .body(ApiResponse.error("Internal server error during route calculation", "INTERNAL_SERVER_ERROR"));
        }
    }

    @GetMapping("/user")
    public ResponseEntity<ApiResponse<Page<RouteResponse>>> getUserRoutes(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            Authentication authentication) {
        try {
            log.info("Getting user routes for: {} - page: {}, size: {}", authentication.getName(), page, size);
            Pageable pageable = PageRequest.of(page, size);
            Page<RouteResponse> routes = userRouteService.getUserRoutes(authentication.getName(), pageable);
            return ResponseEntity.ok(ApiResponse.success(routes, "User routes retrieved successfully"));
        } catch (Exception e) {
            log.error("Error getting user routes for: {}", authentication.getName(), e);
            return ResponseEntity.status(500)
                    .body(ApiResponse.error("Internal server error while fetching user routes", "INTERNAL_SERVER_ERROR"));
        }
    }

    @GetMapping("/{routeId}")
    public ResponseEntity<ApiResponse<RouteResponse>> getRoute(
            @PathVariable Long routeId,
            Authentication authentication) {
        try {
            log.info("Getting route: {} for user: {}", routeId, authentication.getName());
            RouteResponse route = userRouteService.getRoute(routeId, authentication.getName());
            return ResponseEntity.ok(ApiResponse.success(route, "Route retrieved successfully"));
        } catch (Exception e) {
            log.error("Error getting route: {} for user: {}", routeId, authentication.getName(), e);
            return ResponseEntity.status(500)
                    .body(ApiResponse.error("Internal server error while fetching route", "INTERNAL_SERVER_ERROR"));
        }
    }

    @PutMapping("/{routeId}/favorite")
    public ResponseEntity<ApiResponse<RouteResponse>> toggleFavorite(
            @PathVariable Long routeId,
            Authentication authentication) {
        try {
            log.info("Toggling favorite for route: {} by user: {}", routeId, authentication.getName());
            RouteResponse response = userRouteService.toggleFavorite(routeId, authentication.getName());
            return ResponseEntity.ok(ApiResponse.success(response, "Favorite status updated successfully"));
        } catch (Exception e) {
            log.error("Error toggling favorite for route: {} by user: {}", routeId, authentication.getName(), e);
            return ResponseEntity.status(500)
                    .body(ApiResponse.error("Internal server error while toggling favorite", "INTERNAL_SERVER_ERROR"));
        }
    }

    @DeleteMapping("/{routeId}")
    public ResponseEntity<ApiResponse<Map<String, Object>>> deleteRoute(
            @PathVariable Long routeId,
            Authentication authentication) {
        try {
            log.info("Deleting route: {} by user: {}", routeId, authentication.getName());
            userRouteService.deleteRoute(routeId, authentication.getName());
            Map<String, Object> response = new HashMap<>();
            response.put("routeId", routeId);
            response.put("deleted", true);
            response.put("message", "Route deleted successfully");
            return ResponseEntity.ok(ApiResponse.success(response, "Route deleted successfully"));
        } catch (Exception e) {
            log.error("Error deleting route: {} by user: {}", routeId, authentication.getName(), e);
            return ResponseEntity.status(500)
                    .body(ApiResponse.error("Internal server error while deleting route", "INTERNAL_SERVER_ERROR"));
        }
    }

    @GetMapping("/favorites")
    public ResponseEntity<ApiResponse<Page<RouteResponse>>> getFavoriteRoutes(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            Authentication authentication) {
        try {
            log.info("Getting favorite routes for user: {}", authentication.getName());
            Pageable pageable = PageRequest.of(page, size);
            Page<RouteResponse> favoriteRoutes = userRouteService.getFavoriteRoutes(authentication.getName(), pageable);
            return ResponseEntity.ok(ApiResponse.success(favoriteRoutes, "Favorite routes retrieved successfully"));
        } catch (Exception e) {
            log.error("Error getting favorite routes for user: {}", authentication.getName(), e);
            return ResponseEntity.status(500)
                    .body(ApiResponse.error("Internal server error while fetching favorite routes", "INTERNAL_SERVER_ERROR"));
        }
    }

    private Double getDoubleValue(Object value) {
        if (value == null) return null;
        if (value instanceof Double) return (Double) value;
        if (value instanceof Number) return ((Number) value).doubleValue();
        if (value instanceof String) {
            try {
                return Double.parseDouble((String) value);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }
}