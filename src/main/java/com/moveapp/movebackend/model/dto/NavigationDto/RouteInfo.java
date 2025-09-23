package com.moveapp.movebackend.model.dto.NavigationDto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RouteInfo {
    private String fromAddress;
    private String toAddress;
    private Double totalDistance;
    private Integer totalDuration;
    private String routeType;
}
