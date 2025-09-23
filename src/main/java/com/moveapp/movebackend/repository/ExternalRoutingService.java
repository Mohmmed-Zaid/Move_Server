package com.moveapp.movebackend.repository;

import com.moveapp.movebackend.model.dto.RoutesDto.RouteRequest;
import com.moveapp.movebackend.model.entities.Route;

public interface ExternalRoutingService {
    Route calculateRoute(RouteRequest request);
    Route recalculateRoute(Long routeId, double currentLat, double currentLon);
}