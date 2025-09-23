package com.moveapp.movebackend.model.dto.RoutesDto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CoordinateDto {

    @JsonProperty("lat")  // FIXED: Added JSON property mapping for consistency
    private Double latitude;

    @JsonProperty("lng")  // FIXED: Added JSON property mapping for consistency
    private Double longitude;

    // FIXED: Added getters for backwards compatibility with different naming conventions
    public Double getLat() {
        return latitude;
    }

    public Double getLng() {
        return longitude;
    }

    public void setLat(Double lat) {
        this.latitude = lat;
    }

    public void setLng(Double lng) {
        this.longitude = lng;
    }
}