package com.moveapp.movebackend.model.dto.LocationDto;

import com.moveapp.movebackend.model.enums.LocationCategory;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LocationDto {
    private Long id;
    private String address;
    private Double latitude;
    private Double longitude;
    private String placeId;
    private LocationCategory category;
    private Boolean isPopular;
}
