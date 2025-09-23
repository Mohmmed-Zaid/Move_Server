package com.moveapp.movebackend.model.dto.RoutesDto;

import com.moveapp.movebackend.model.enums.RouteType;
import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RouteRequest {
    @NotBlank(message = "From address is required")
    private String fromAddress;

    @NotNull(message = "From latitude is required")
    @DecimalMin(value = "-90.0", message = "Latitude must be between -90 and 90")
    @DecimalMax(value = "90.0", message = "Latitude must be between -90 and 90")
    private Double fromLatitude;

    @NotNull(message = "From longitude is required")
    @DecimalMin(value = "-180.0", message = "Longitude must be between -180 and 180")
    @DecimalMax(value = "180.0", message = "Longitude must be between -180 and 180")
    private Double fromLongitude;

    @NotBlank(message = "To address is required")
    private String toAddress;

    @NotNull(message = "To latitude is required")
    @DecimalMin(value = "-90.0", message = "Latitude must be between -90 and 90")
    @DecimalMax(value = "90.0", message = "Latitude must be between -90 and 90")
    private Double toLatitude;

    @NotNull(message = "To longitude is required")
    @DecimalMin(value = "-180.0", message = "Longitude must be between -180 and 180")
    @DecimalMax(value = "180.0", message = "Longitude must be between -180 and 180")
    private Double toLongitude;

    @Builder.Default  // FIXED: Added @Builder.Default annotation
    private RouteType routeType = RouteType.DRIVING;

    @Builder.Default  // FIXED: Added @Builder.Default annotation
    private boolean avoidTolls = false;

    @Builder.Default  // FIXED: Added @Builder.Default annotation
    private boolean avoidHighways = false;
}