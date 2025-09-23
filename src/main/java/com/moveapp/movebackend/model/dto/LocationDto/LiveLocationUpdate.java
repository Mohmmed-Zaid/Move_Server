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
public class LiveLocationUpdate {
    private Long userId;
    private String userEmail;
    private String userName;
    private Double latitude;
    private Double longitude;
    private Double accuracy;
    private Double speed;
    private Double bearing;
    private String address;
    private LocalDateTime timestamp;
}

