package com.moveapp.movebackend.model.dto.OTPdto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SendOtpRequest {

    @NotBlank(message = "Email is required")
    @Email(message = "Email should be valid")
    private String email;

    @NotBlank(message = "OTP type is required")
    @Pattern(regexp = "SIGNUP_VERIFICATION|PASSWORD_RESET|EMAIL_VERIFICATION",
            message = "Invalid OTP type")
    private String type;
}