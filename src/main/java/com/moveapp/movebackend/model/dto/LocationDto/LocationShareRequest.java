package com.moveapp.movebackend.model.dto.LocationDto;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LocationShareRequest {
    @NotNull(message = "Enabled flag is required")
    private Boolean enabled;
}

