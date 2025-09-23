package com.moveapp.movebackend.controller;

import com.moveapp.movebackend.model.dto.NavigationDto.*;
import com.moveapp.movebackend.service.NavigationServiceImpl;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/navigation")
@RequiredArgsConstructor
@Slf4j
public class NavigationController {

    private final NavigationServiceImpl navigationService;

    @PostMapping("/start")
    public ResponseEntity<NavigationResponse> startNavigation(
            @Valid @RequestBody StartNavigationRequest request,
            Authentication authentication) {

        log.info("Starting navigation for route {} by user {}",
                request.getRouteId(), authentication.getName());

        NavigationResponse response = navigationService.startNavigation(
                authentication.getName(), request);

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PutMapping("/update")
    public ResponseEntity<NavigationResponse> updateLocation(
            @Valid @RequestBody LocationUpdateRequest request,
            Authentication authentication) {

        NavigationResponse response = navigationService.updateLocation(
                authentication.getName(), request);

        return ResponseEntity.ok(response);
    }

    @PutMapping("/complete/{sessionId}")
    public ResponseEntity<NavigationResponse> completeNavigation(
            @PathVariable Long sessionId,
            Authentication authentication) {

        log.info("Completing navigation session {} for user {}",
                sessionId, authentication.getName());

        NavigationResponse response = navigationService.completeNavigation(
                sessionId, authentication.getName());

        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/stop/{sessionId}")
    public ResponseEntity<Void> stopNavigation(
            @PathVariable Long sessionId,
            Authentication authentication) {

        log.info("Stopping navigation session {} for user {}",
                sessionId, authentication.getName());

        navigationService.stopNavigation(sessionId, authentication.getName());

        return ResponseEntity.noContent().build();
    }

    @GetMapping("/status")
    public ResponseEntity<NavigationStatusResponse> getNavigationStatus(
            Authentication authentication) {

        NavigationStatusResponse response = navigationService.getNavigationStatus(
                authentication.getName());

        return ResponseEntity.ok(response);
    }

    @GetMapping("/history")
    public ResponseEntity<Page<NavigationResponse>> getNavigationHistory(
            @PageableDefault(size = 20, sort = "startTime") Pageable pageable,
            Authentication authentication) {

        Page<NavigationResponse> response = navigationService.getNavigationHistory(
                authentication.getName(), pageable);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/stats")
    public ResponseEntity<NavigationStatsResponse> getNavigationStats(
            Authentication authentication) {

        NavigationStatsResponse response = navigationService.getNavigationStats(
                authentication.getName());

        return ResponseEntity.ok(response);
    }
}