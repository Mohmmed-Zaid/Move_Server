package com.moveapp.movebackend.service.external;

import com.moveapp.movebackend.model.dto.RoutesDto.CoordinateDto;
import com.moveapp.movebackend.model.dto.RoutesDto.RouteRequest;
import com.moveapp.movebackend.model.entities.Route;
import com.moveapp.movebackend.model.enums.RouteType;
import com.moveapp.movebackend.model.enums.TrafficCondition;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.moveapp.movebackend.repository.ExternalRoutingService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class ExternalRoutingServiceImpl implements ExternalRoutingService {

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    @Value("${move.external.osrm.routing-url:https://router.project-osrm.org}")
    private String osrmUrl;

    public Route calculateRoute(RouteRequest request) {
        try {
            log.info("Calculating route using external service for: {} to {}",
                    request.getFromAddress(), request.getToAddress());

            String routeUrl = String.format(
                    "%s/route/v1/driving/%s,%s;%s,%s?overview=full&geometries=geojson&steps=true",
                    osrmUrl,
                    request.getFromLongitude(),
                    request.getFromLatitude(),
                    request.getToLongitude(),
                    request.getToLatitude()
            );

            Map<String, Object> osrmResponse = restTemplate.getForObject(routeUrl, Map.class);

            if (osrmResponse != null && "Ok".equals(osrmResponse.get("code"))) {
                List<Map<String, Object>> routes = (List<Map<String, Object>>) osrmResponse.get("routes");

                if (!routes.isEmpty()) {
                    Map<String, Object> routeData = routes.get(0);
                    Map<String, Object> geometry = (Map<String, Object>) routeData.get("geometry");
                    List<List<Double>> coordinates = (List<List<Double>>) geometry.get("coordinates");

                    // Convert coordinates to our format
                    List<Map<String, Double>> formattedCoordinates = new ArrayList<>();
                    for (List<Double> coord : coordinates) {
                        Map<String, Double> point = new HashMap<>();
                        point.put("lat", coord.get(1));
                        point.put("lng", coord.get(0));
                        formattedCoordinates.add(point);
                    }

                    // Convert distance from meters to kilometers
                    Double distanceKm = ((Number) routeData.get("distance")).doubleValue() / 1000.0;

                    // FIXED: Convert duration from seconds to minutes as Double (not Integer)
                    Double durationMinutes = Math.ceil(((Number) routeData.get("duration")).doubleValue() / 60.0);

                    // Create route entity
                    Route route = Route.builder()
                            .fromAddress(request.getFromAddress())
                            .toAddress(request.getToAddress())
                            .fromLatitude(request.getFromLatitude())
                            .fromLongitude(request.getFromLongitude())
                            .toLatitude(request.getToLatitude())
                            .toLongitude(request.getToLongitude())
                            .distance(distanceKm)
                            .duration(durationMinutes)
                            .routeType(request.getRouteType() != null ? request.getRouteType() : RouteType.DRIVING)
                            .isFavorite(false)
                            .build();

                    // Store coordinates as JSON string
                    try {
                        route.setRouteCoordinates(objectMapper.writeValueAsString(formattedCoordinates));
                    } catch (Exception e) {
                        log.warn("Failed to serialize coordinates: {}", e.getMessage());
                        route.setRouteCoordinates("[]");
                    }

                    log.info("Route calculated successfully: {}km, {}min", distanceKm, durationMinutes);
                    return route;
                }
            }

            throw new RuntimeException("No route found from external service");

        } catch (Exception e) {
            log.error("Failed to calculate route using external service: {}", e.getMessage(), e);
            throw new RuntimeException("Route calculation failed: " + e.getMessage(), e);
        }
    }
    @Override
    public Route recalculateRoute(Long routeId, double currentLat, double currentLon) {
        log.info("Recalculating route {} from current position ({}, {})", routeId, currentLat, currentLon);
        throw new UnsupportedOperationException("Route recalculation not yet implemented");
    }

    private Route createMockRoute(double fromLat, double fromLon, double toLat, double toLon,
                                  RouteType routeType, String fromAddress, String toAddress) {
        double distance = calculateDistance(fromLat, fromLon, toLat, toLon);
        int duration = (int) estimateDuration(distance, routeType);
        List<CoordinateDto> coordinates = createMockCoordinatePath(fromLat, fromLon, toLat, toLon);

        String coordinatesJson;
        try {
            coordinatesJson = objectMapper.writeValueAsString(coordinates);
        } catch (Exception e) {
            log.error("Failed to serialize coordinates", e);
            coordinatesJson = "[]";
        }

        return Route.builder()
                .fromAddress(fromAddress)
                .toAddress(toAddress)
                .fromLatitude(fromLat)
                .fromLongitude(fromLon)
                .toLatitude(toLat)
                .toLongitude(toLon)
                .distance(distance)
                .duration((double) duration)
                .routeType(routeType)
                .isFavorite(false)
                .trafficCondition(TrafficCondition.MODERATE)
                .routeCoordinates(coordinatesJson)
                .routeInstructions("[]")
                .createdAt(LocalDateTime.now())
                .build();
    }

    private List<CoordinateDto> createMockCoordinatePath(double fromLat, double fromLon, double toLat, double toLon) {
        List<CoordinateDto> coordinates = new ArrayList<>();
        coordinates.add(new CoordinateDto(fromLat, fromLon));

        int numPoints = 5;
        for (int i = 1; i < numPoints; i++) {
            double ratio = (double) i / numPoints;
            double lat = fromLat + (toLat - fromLat) * ratio;
            double lon = fromLon + (toLon - fromLon) * ratio;
            coordinates.add(new CoordinateDto(lat, lon));
        }

        coordinates.add(new CoordinateDto(toLat, toLon));
        return coordinates;
    }

    private double calculateDistance(double lat1, double lon1, double lat2, double lon2) {
        final int R = 6371;
        double latDistance = Math.toRadians(lat2 - lat1);
        double lonDistance = Math.toRadians(lon2 - lon1);

        double a = Math.sin(latDistance / 2) * Math.sin(latDistance / 2)
                + Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2))
                * Math.sin(lonDistance / 2) * Math.sin(lonDistance / 2);

        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        return R * c;
    }

    private double estimateDuration(double distanceKm, RouteType routeType) {
        double speedKmh = switch (routeType) {
            case DRIVING -> 50.0;
            case FASTEST -> 60.0;  // Added case for FASTEST if you want to keep it
            case WALKING -> 5.0;
            case CYCLING -> 15.0;
            case TRANSIT -> 30.0;
            case SHORTEST -> 40.0;
            case BALANCED -> 45.0;
            case AVOID_HIGHWAYS -> 40.0;
            case AVOID_TOLLS -> 45.0;
        };
        return Math.round((distanceKm / speedKmh) * 60);  // Returns Double
    }
}