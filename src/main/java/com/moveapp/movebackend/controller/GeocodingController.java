package com.moveapp.movebackend.controller;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/geocoding")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = {"http://localhost:5173", "http://localhost:3000"})
public class GeocodingController {

    private final RestTemplate restTemplate;

    @Value("${move.external.osm.nominatim-url:https://nominatim.openstreetmap.org}")
    private String nominatimUrl;

    @Value("${move.external.osm.timeout:15000}")
    private int timeout;

    @GetMapping("/search")
    public ResponseEntity<ApiResponse<List<Map<String, Object>>>> searchLocations(@RequestParam String query) {
        try {
            log.info("Geocoding search for: {}", query);

            if (query == null || query.trim().length() < 2) {
                return ResponseEntity.badRequest()
                        .body(ApiResponse.<List<Map<String, Object>>>builder()
                                .success(false)
                                .message("Query must be at least 2 characters long")
                                .error("INVALID_QUERY_LENGTH")
                                .timestamp(System.currentTimeMillis())
                                .build());
            }

            String url = UriComponentsBuilder
                    .fromHttpUrl(nominatimUrl + "/search")
                    .queryParam("q", query.trim())
                    .queryParam("format", "json")
                    .queryParam("addressdetails", "1")
                    .queryParam("limit", "5")
                    .queryParam("countrycodes", "in")
                    .queryParam("accept-language", "en")
                    .build()
                    .toUriString();

            org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
            headers.set("User-Agent", "MapGuide-App/1.0 (contact@mapguide.com)");

            org.springframework.http.HttpEntity<?> entity = new org.springframework.http.HttpEntity<>(headers);

            try {
                ResponseEntity<List> response = restTemplate.exchange(
                        url,
                        org.springframework.http.HttpMethod.GET,
                        entity,
                        List.class
                );

                List<Map<String, Object>> results = response.getBody();

                if (results != null && !results.isEmpty()) {
                    log.info("Found {} geocoding results for query: {}", results.size(), query);
                    return ResponseEntity.ok(ApiResponse.<List<Map<String, Object>>>builder()
                            .success(true)
                            .message("Locations found successfully")
                            .data(results)
                            .timestamp(System.currentTimeMillis())
                            .build());
                } else {
                    log.info("No geocoding results found for query: {}", query);
                    return ResponseEntity.ok(ApiResponse.<List<Map<String, Object>>>builder()
                            .success(true)
                            .message("No locations found for the given query")
                            .data(List.of())
                            .timestamp(System.currentTimeMillis())
                            .build());
                }
            } catch (org.springframework.web.client.RestClientException e) {
                log.error("RestTemplate error for query: {}", query, e);
                return ResponseEntity.status(503)
                        .body(ApiResponse.<List<Map<String, Object>>>builder()
                                .success(false)
                                .message("Geocoding service temporarily unavailable")
                                .error("SERVICE_UNAVAILABLE")
                                .timestamp(System.currentTimeMillis())
                                .build());
            }

        } catch (Exception e) {
            log.error("Error during geocoding search for query: {}", query, e);
            return ResponseEntity.status(500)
                    .body(ApiResponse.<List<Map<String, Object>>>builder()
                            .success(false)
                            .message("Internal server error during geocoding")
                            .error("INTERNAL_SERVER_ERROR")
                            .timestamp(System.currentTimeMillis())
                            .build());
        }
    }

    @GetMapping("/reverse")
    public ResponseEntity<ApiResponse<Map<String, Object>>> reverseGeocode(
            @RequestParam double lat,
            @RequestParam double lng) {
        try {
            log.info("Reverse geocoding for coordinates: {}, {}", lat, lng);

            if (lat < -90 || lat > 90 || lng < -180 || lng > 180) {
                return ResponseEntity.badRequest()
                        .body(ApiResponse.<Map<String, Object>>builder()
                                .success(false)
                                .message("Invalid coordinates provided")
                                .error("INVALID_COORDINATES")
                                .timestamp(System.currentTimeMillis())
                                .build());
            }

            String url = UriComponentsBuilder
                    .fromHttpUrl(nominatimUrl + "/reverse")
                    .queryParam("lat", lat)
                    .queryParam("lon", lng)
                    .queryParam("format", "json")
                    .queryParam("addressdetails", "1")
                    .queryParam("accept-language", "en")
                    .build()
                    .toUriString();

            org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
            headers.set("User-Agent", "MapGuide-App/1.0 (contact@mapguide.com)");

            org.springframework.http.HttpEntity<?> entity = new org.springframework.http.HttpEntity<>(headers);

            try {
                ResponseEntity<Map> response = restTemplate.exchange(
                        url,
                        org.springframework.http.HttpMethod.GET,
                        entity,
                        Map.class
                );

                Map<String, Object> result = response.getBody();

                if (result != null) {
                    log.info("Reverse geocoding successful for coordinates: {}, {}", lat, lng);
                    return ResponseEntity.ok(ApiResponse.<Map<String, Object>>builder()
                            .success(true)
                            .message("Location found successfully")
                            .data(result)
                            .timestamp(System.currentTimeMillis())
                            .build());
                } else {
                    return ResponseEntity.notFound().build();
                }
            } catch (org.springframework.web.client.RestClientException e) {
                log.error("RestTemplate error for reverse geocoding: {}, {}", lat, lng, e);
                return ResponseEntity.status(503)
                        .body(ApiResponse.<Map<String, Object>>builder()
                                .success(false)
                                .message("Reverse geocoding service temporarily unavailable")
                                .error("SERVICE_UNAVAILABLE")
                                .timestamp(System.currentTimeMillis())
                                .build());
            }

        } catch (Exception e) {
            log.error("Error during reverse geocoding for coordinates: {}, {}", lat, lng, e);
            return ResponseEntity.status(500)
                    .body(ApiResponse.<Map<String, Object>>builder()
                            .success(false)
                            .message("Internal server error during reverse geocoding")
                            .error("INTERNAL_SERVER_ERROR")
                            .timestamp(System.currentTimeMillis())
                            .build());
        }
    }

    @GetMapping("/suggestions")
    public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getLocationSuggestions(@RequestParam String query) {
        try {
            log.info("Getting location suggestions for: {}", query);

            if (query == null || query.trim().length() < 2) {
                return ResponseEntity.badRequest()
                        .body(ApiResponse.<List<Map<String, Object>>>builder()
                                .success(false)
                                .message("Query must be at least 2 characters long")
                                .error("INVALID_QUERY_LENGTH")
                                .timestamp(System.currentTimeMillis())
                                .build());
            }

            String url = UriComponentsBuilder
                    .fromHttpUrl(nominatimUrl + "/search")
                    .queryParam("q", query.trim())
                    .queryParam("format", "json")
                    .queryParam("addressdetails", "1")
                    .queryParam("limit", "8")
                    .queryParam("countrycodes", "in")
                    .queryParam("accept-language", "en")
                    .queryParam("dedupe", "1")
                    .build()
                    .toUriString();

            org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
            headers.set("User-Agent", "MapGuide-App/1.0 (contact@mapguide.com)");

            org.springframework.http.HttpEntity<?> entity = new org.springframework.http.HttpEntity<>(headers);

            try {
                ResponseEntity<List> response = restTemplate.exchange(
                        url,
                        org.springframework.http.HttpMethod.GET,
                        entity,
                        List.class
                );

                List<Map<String, Object>> results = response.getBody();

                if (results != null) {
                    List<Map<String, Object>> filteredResults = results.stream()
                            .filter(result -> {
                                String displayName = (String) result.get("display_name");
                                return displayName != null &&
                                        displayName.toLowerCase().contains("india") &&
                                        result.get("lat") != null &&
                                        result.get("lon") != null;
                            })
                            .limit(5)
                            .toList();

                    log.info("Returning {} filtered suggestions for query: {}", filteredResults.size(), query);
                    return ResponseEntity.ok(ApiResponse.<List<Map<String, Object>>>builder()
                            .success(true)
                            .message("Location suggestions retrieved successfully")
                            .data(filteredResults)
                            .timestamp(System.currentTimeMillis())
                            .build());
                } else {
                    return ResponseEntity.ok(ApiResponse.<List<Map<String, Object>>>builder()
                            .success(true)
                            .message("No suggestions found")
                            .data(List.of())
                            .timestamp(System.currentTimeMillis())
                            .build());
                }
            } catch (org.springframework.web.client.RestClientException e) {
                log.error("RestTemplate error for suggestions: {}", query, e);
                return ResponseEntity.status(503)
                        .body(ApiResponse.<List<Map<String, Object>>>builder()
                                .success(false)
                                .message("Location suggestions service temporarily unavailable")
                                .error("SERVICE_UNAVAILABLE")
                                .timestamp(System.currentTimeMillis())
                                .build());
            }

        } catch (Exception e) {
            log.error("Error getting location suggestions for query: {}", query, e);
            return ResponseEntity.status(500)
                    .body(ApiResponse.<List<Map<String, Object>>>builder()
                            .success(false)
                            .message("Internal server error during location suggestions")
                            .error("INTERNAL_SERVER_ERROR")
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