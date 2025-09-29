package com.moveapp.movebackend.controller;

import com.moveapp.movebackend.model.dto.ApiResponse;
import com.moveapp.movebackend.model.dto.NavigationDto.*;
import com.moveapp.movebackend.service.NavigationServiceImpl;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/navigation")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = {"http://localhost:5173", "http://localhost:3000"})
public class NavigationController {

    private final NavigationServiceImpl navigationService;

    @PostMapping("/start")
    public ResponseEntity<ApiResponse<NavigationResponse>> startNavigation(
            @Valid @RequestBody StartNavigationRequest request,
            Authentication authentication) {

        try {
            log.info("Starting navigation for route {} by user {}",
                    request.getRouteId(), authentication.getName());

            NavigationResponse response = navigationService.startNavigation(
                    authentication.getName(), request);

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(ApiResponse.<NavigationResponse>success(response, "Navigation started successfully"));

        } catch (Exception e) {
            log.error("Error starting navigation for user: {}", authentication.getName(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.<NavigationResponse>error(
                            "Failed to start navigation: " + e.getMessage(),
                            "NAVIGATION_START_ERROR"));
        }
    }

    @PutMapping("/update")
    public ResponseEntity<ApiResponse<NavigationResponse>> updateLocation(
            @Valid @RequestBody LocationUpdateRequest request,
            Authentication authentication) {

        try {
            NavigationResponse response = navigationService.updateLocation(
                    authentication.getName(), request);

            return ResponseEntity.ok(ApiResponse.<NavigationResponse>success(response, "Location updated successfully"));

        } catch (Exception e) {
            log.error("Error updating navigation location for user: {}", authentication.getName(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.<NavigationResponse>error(
                            "Failed to update location: " + e.getMessage(),
                            "NAVIGATION_UPDATE_ERROR"));
        }
    }

    @PutMapping("/complete/{sessionId}")
    public ResponseEntity<ApiResponse<NavigationResponse>> completeNavigation(
            @PathVariable Long sessionId,
            Authentication authentication) {

        try {
            log.info("Completing navigation session {} for user {}",
                    sessionId, authentication.getName());

            NavigationResponse response = navigationService.completeNavigation(
                    sessionId, authentication.getName());

            return ResponseEntity.ok(ApiResponse.<NavigationResponse>success(response, "Navigation completed successfully"));

        } catch (Exception e) {
            log.error("Error completing navigation session {} for user: {}", sessionId, authentication.getName(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.<NavigationResponse>error(
                            "Failed to complete navigation: " + e.getMessage(),
                            "NAVIGATION_COMPLETE_ERROR"));
        }
    }

    @DeleteMapping("/stop/{sessionId}")
    public ResponseEntity<ApiResponse<Map<String, Object>>> stopNavigation(
            @PathVariable Long sessionId,
            Authentication authentication) {

        try {
            log.info("Stopping navigation session {} for user {}",
                    sessionId, authentication.getName());

            navigationService.stopNavigation(sessionId, authentication.getName());

            Map<String, Object> result = new HashMap<>();
            result.put("sessionId", sessionId);
            result.put("stopped", true);
            result.put("timestamp", LocalDateTime.now());

            return ResponseEntity.ok(ApiResponse.<Map<String, Object>>success(result, "Navigation stopped successfully"));

        } catch (Exception e) {
            log.error("Error stopping navigation session {} for user: {}", sessionId, authentication.getName(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.<Map<String, Object>>error(
                            "Failed to stop navigation: " + e.getMessage(),
                            "NAVIGATION_STOP_ERROR"));
        }
    }

    @GetMapping("/status")
    public ResponseEntity<ApiResponse<NavigationStatusResponse>> getNavigationStatus(
            Authentication authentication) {

        try {
            NavigationStatusResponse response = navigationService.getNavigationStatus(
                    authentication.getName());

            return ResponseEntity.ok(ApiResponse.<NavigationStatusResponse>success(response, "Navigation status retrieved successfully"));

        } catch (Exception e) {
            log.error("Error getting navigation status for user: {}", authentication.getName(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.<NavigationStatusResponse>error(
                            "Failed to get navigation status: " + e.getMessage(),
                            "NAVIGATION_STATUS_ERROR"));
        }
    }

    @GetMapping("/history")
    public ResponseEntity<ApiResponse<Page<NavigationResponse>>> getNavigationHistory(
            @PageableDefault(size = 20, sort = {"startTime"}) Pageable pageable,
            Authentication authentication) {

        try {
            Page<NavigationResponse> response = navigationService.getNavigationHistory(
                    authentication.getName(), pageable);

            return ResponseEntity.ok(ApiResponse.<Page<NavigationResponse>>success(response, "Navigation history retrieved successfully"));

        } catch (Exception e) {
            log.error("Error getting navigation history for user: {}", authentication.getName(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.<Page<NavigationResponse>>error(
                            "Failed to get navigation history: " + e.getMessage(),
                            "NAVIGATION_HISTORY_ERROR"));
        }
    }

    @GetMapping("/stats")
    public ResponseEntity<ApiResponse<NavigationStatsResponse>> getNavigationStats(
            Authentication authentication) {

        try {
            NavigationStatsResponse response = navigationService.getNavigationStats(
                    authentication.getName());

            return ResponseEntity.ok(ApiResponse.<NavigationStatsResponse>success(response, "Navigation stats retrieved successfully"));

        } catch (Exception e) {
            log.error("Error getting navigation stats for user: {}", authentication.getName(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.<NavigationStatsResponse>error(
                            "Failed to get navigation stats: " + e.getMessage(),
                            "NAVIGATION_STATS_ERROR"));
        }
    }
}