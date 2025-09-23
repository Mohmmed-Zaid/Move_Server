package com.moveapp.movebackend.model.dto.NavigationDto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RealTimeUpdate {
    private Long sessionId;
    private String updateType; // NAVIGATION_STARTED, LOCATION_UPDATE, OFF_ROUTE, etc.
    private NavigationResponse navigationData;
    private String message;
    private LocalDateTime timestamp;
}