package com.moveapp.movebackend.model.dto.OTPdto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OtpResponse {
    private Boolean success;
    private String message;
    private Integer remainingAttempts;
    private Long expiresInMinutes;
    private String email;
    private String type;
    private Long nextAllowedTime;
}