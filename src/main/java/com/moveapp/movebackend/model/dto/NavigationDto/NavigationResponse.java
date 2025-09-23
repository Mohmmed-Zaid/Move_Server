package com.moveapp.movebackend.model.dto.NavigationDto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor

public class NavigationResponse {
    private Long sessionId;
    private Long routeId;
    private String routeName;
    private Double currentLatitude;
    private Double currentLongitude;
    private Double remainingDistance;
    private Integer remainingTime;
    private String formattedDistance;
    private String formattedTime;
    private Boolean isActive;
    private Boolean isOffRoute;
    private LocalDateTime startTime;
    private LocalDateTime lastUpdated;
    private RouteInfo routeInfo;
    private String speedWarning;
}