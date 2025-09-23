package com.moveapp.movebackend.model.dto.NavigationDto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NavigationStatsResponse {
    private Long totalNavigations;
    private Long totalNavigationsThisWeek;
    private Long totalNavigationsThisMonth;
    private Double totalDistanceNavigated; // km
    private Integer totalTimeNavigated; // minutes
    private Double averageSpeed; // km/h
}

