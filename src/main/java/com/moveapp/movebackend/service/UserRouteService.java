package com.moveapp.movebackend.service;

import com.moveapp.movebackend.model.dto.RoutesDto.RouteRequest;
import com.moveapp.movebackend.model.dto.RoutesDto.RouteResponse;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface UserRouteService {
    RouteResponse calculateRoute(String userEmail, RouteRequest request);
    Page<RouteResponse> getUserRoutes(String userEmail, Pageable pageable);
    RouteResponse getRoute(Long routeId, String userEmail);
    RouteResponse toggleFavorite(Long routeId, String userEmail);
    void deleteRoute(Long routeId, String userEmail);
    Page<RouteResponse> getFavoriteRoutes(String userEmail, Pageable pageable);
}