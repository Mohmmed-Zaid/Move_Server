package com.moveapp.movebackend.model.dto.RoutesDto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.moveapp.movebackend.model.enums.RouteType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RouteResponse {

    private Long id;
    private String fromAddress;
    private Double fromLatitude;
    private Double fromLongitude;
    private String toAddress;
    private Double toLatitude;
    private Double toLongitude;
    private Double distance;
    private Double duration;
    private String formattedDistance;
    private String formattedDuration;
    private RouteType routeType;
    private Boolean isFavorite;
    private List<CoordinateDto> coordinates;

    private String trafficCondition;
    private String routeCoordinates;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime createdAt;
}
