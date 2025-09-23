package com.moveapp.movebackend.model.dto.LocationDto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LocationSearchResponse {
    private List<LocationDto> results;
    private Integer totalResult;
    private Integer page;
    private Integer size;
    private Boolean hasNext;
    private Boolean hasPrevious;
    private String query;
    private Long searchTimeMs;
}
