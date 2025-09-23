package com.moveapp.movebackend.model.dto.OTPdto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VerifyOtpRequest {

    @NotBlank(message = "Email is required")
    @Email(message = "Please provide a valid email address")
    private String email;

    @NotBlank(message = "OTP is required")
    @Pattern(regexp = "^[0-9]{6}$", message = "OTP must be exactly 6 digits")
    private String otp;

    @NotBlank(message = "OTP type is required")
    @Pattern(
            regexp = "SIGNUP_VERIFICATION|PASSWORD_RESET|EMAIL_VERIFICATION",
            message = "Invalid OTP type. Allowed values: SIGNUP_VERIFICATION, PASSWORD_RESET, EMAIL_VERIFICATION"
    )
    private String type;
}
