package com.moveapp.movebackend.model.dto.LocationDto;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NearbyUsersResponse {
    private Long userId;
    private String userName;
    private String userEmail;
    private Double latitude;
    private Double longitude;
    private Double distance; // km
    private String address;
    private LocalDateTime lastUpdated;
}