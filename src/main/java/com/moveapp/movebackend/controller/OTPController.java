package com.moveapp.movebackend.controller;

import com.moveapp.movebackend.model.dto.OTPdto.SendOtpRequest;
import com.moveapp.movebackend.model.dto.OTPdto.OtpResponse;
import com.moveapp.movebackend.model.dto.OTPdto.VerifyOtpRequest;
import com.moveapp.movebackend.model.dto.OTPdto.SignupWithOtpRequest;
import com.moveapp.movebackend.model.dto.AuthenticationDto.AuthResponse;
import com.moveapp.movebackend.service.OTPService;
import com.moveapp.movebackend.service.AuthServiceImpl;
import com.moveapp.movebackend.model.enums.OTPType;
import jakarta.validation.Valid;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/otp")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = {"http://localhost:5173", "move-ui-three.vercel.app"})
public class OTPController {

    private final OTPService otpService;
    private final AuthServiceImpl authService;

    @PostMapping("/send")
    public ResponseEntity<ApiResponse<OtpResponse>> sendOtp(
            @Valid @RequestBody SendOtpRequest request,
            BindingResult bindingResult) {

        if (bindingResult.hasErrors()) {
            String errorMessage = bindingResult.getFieldErrors().stream()
                    .map(error -> error.getField() + ": " + error.getDefaultMessage())
                    .collect(Collectors.joining(", "));

            log.warn("Validation errors for OTP send request: {}", errorMessage);
            return ResponseEntity.badRequest()
                    .body(ApiResponse.<OtpResponse>builder()
                            .success(false)
                            .message("Validation failed: " + errorMessage)
                            .error("VALIDATION_ERROR")
                            .timestamp(System.currentTimeMillis())
                            .build());
        }

        try {
            log.info("OTP send request for email: {} and type: {}", request.getEmail(), request.getType());

            if (!isValidOtpType(request.getType())) {
                log.warn("Invalid OTP type received: {}", request.getType());
                return ResponseEntity.badRequest()
                        .body(ApiResponse.<OtpResponse>builder()
                                .success(false)
                                .message("Invalid OTP type. Must be SIGNUP_VERIFICATION or PASSWORD_RESET")
                                .error("INVALID_OTP_TYPE")
                                .timestamp(System.currentTimeMillis())
                                .build());
            }

            if (request.getEmail() == null || !isValidEmail(request.getEmail())) {
                log.warn("Invalid email format: {}", request.getEmail());
                return ResponseEntity.badRequest()
                        .body(ApiResponse.<OtpResponse>builder()
                                .success(false)
                                .message("Invalid email format")
                                .error("INVALID_EMAIL")
                                .timestamp(System.currentTimeMillis())
                                .build());
            }

            OtpResponse response = otpService.sendOtp(request);

            if (!response.getSuccess()) {
                return ResponseEntity.badRequest()
                        .body(ApiResponse.<OtpResponse>builder()
                                .success(false)
                                .message(response.getMessage())
                                .error("OTP_SERVICE_ERROR")
                                .data(response)
                                .timestamp(System.currentTimeMillis())
                                .build());
            }

            return ResponseEntity.ok(ApiResponse.<OtpResponse>builder()
                    .success(true)
                    .message("OTP sent successfully")
                    .data(response)
                    .timestamp(System.currentTimeMillis())
                    .build());

        } catch (Exception e) {
            log.error("Error sending OTP for email: {}", request.getEmail(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.<OtpResponse>builder()
                            .success(false)
                            .message("Internal server error occurred")
                            .error("INTERNAL_SERVER_ERROR")
                            .timestamp(System.currentTimeMillis())
                            .build());
        }
    }

    @PostMapping("/verify")
    public ResponseEntity<ApiResponse<OtpResponse>> verifyOtp(
            @Valid @RequestBody VerifyOtpRequest request,
            BindingResult bindingResult) {

        if (bindingResult.hasErrors()) {
            String errorMessage = bindingResult.getFieldErrors().stream()
                    .map(error -> error.getField() + ": " + error.getDefaultMessage())
                    .collect(Collectors.joining(", "));

            log.warn("Validation errors for OTP verify request: {}", errorMessage);
            return ResponseEntity.badRequest()
                    .body(ApiResponse.<OtpResponse>builder()
                            .success(false)
                            .message("Validation failed: " + errorMessage)
                            .error("VALIDATION_ERROR")
                            .timestamp(System.currentTimeMillis())
                            .build());
        }

        try {
            log.info("OTP verify request for email: {} and type: {}", request.getEmail(), request.getType());

            OtpResponse response = otpService.verifyOtp(request);

            // Return the response based on success/failure
            HttpStatus status = response.getSuccess() ? HttpStatus.OK : HttpStatus.BAD_REQUEST;

            return ResponseEntity.status(status)
                    .body(ApiResponse.<OtpResponse>builder()
                            .success(response.getSuccess())
                            .message(response.getMessage())
                            .data(response)
                            .timestamp(System.currentTimeMillis())
                            .build());

        } catch (Exception e) {
            log.error("Error verifying OTP for email: {}", request.getEmail(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.<OtpResponse>builder()
                            .success(false)
                            .message("Internal server error occurred")
                            .error("INTERNAL_SERVER_ERROR")
                            .timestamp(System.currentTimeMillis())
                            .build());
        }
    }

    @PostMapping("/verify-signup-otp")
    public ResponseEntity<ApiResponse<OtpResponse>> verifySignupOtp(
            @Valid @RequestBody VerifyOtpRequest request,
            BindingResult bindingResult) {

        if (bindingResult.hasErrors()) {
            String errorMessage = bindingResult.getFieldErrors().stream()
                    .map(error -> error.getField() + ": " + error.getDefaultMessage())
                    .collect(Collectors.joining(", "));

            log.warn("Validation errors for signup OTP verify request: {}", errorMessage);
            return ResponseEntity.badRequest()
                    .body(ApiResponse.<OtpResponse>builder()
                            .success(false)
                            .message("Validation failed: " + errorMessage)
                            .error("VALIDATION_ERROR")
                            .timestamp(System.currentTimeMillis())
                            .build());
        }

        try {
            log.info("Verify signup OTP request for email: {}", request.getEmail());

            // Force the type to be SIGNUP_VERIFICATION
            VerifyOtpRequest modifiedRequest = VerifyOtpRequest.builder()
                    .email(request.getEmail())
                    .otp(request.getOtp())
                    .type("SIGNUP_VERIFICATION")
                    .build();

            OtpResponse response = otpService.verifyOtpForSignup(modifiedRequest);

            HttpStatus status = response.getSuccess() ? HttpStatus.OK : HttpStatus.BAD_REQUEST;

            return ResponseEntity.status(status)
                    .body(ApiResponse.<OtpResponse>builder()
                            .success(response.getSuccess())
                            .message(response.getMessage())
                            .data(response)
                            .timestamp(System.currentTimeMillis())
                            .build());

        } catch (Exception e) {
            log.error("Error verifying signup OTP for email: {}", request.getEmail(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.<OtpResponse>builder()
                            .success(false)
                            .message("Internal server error occurred")
                            .error("INTERNAL_SERVER_ERROR")
                            .timestamp(System.currentTimeMillis())
                            .build());
        }
    }

    @PostMapping("/signup-with-otp")
    public ResponseEntity<ApiResponse<AuthResponse>> signupWithOtp(
            @Valid @RequestBody SignupWithOtpRequest request,
            BindingResult bindingResult) {

        if (bindingResult.hasErrors()) {
            String errorMessage = bindingResult.getFieldErrors().stream()
                    .map(error -> error.getField() + ": " + error.getDefaultMessage())
                    .collect(Collectors.joining(", "));

            log.warn("Validation errors for signup with OTP request: {}", errorMessage);
            return ResponseEntity.badRequest()
                    .body(ApiResponse.<AuthResponse>builder()
                            .success(false)
                            .message("Validation failed: " + errorMessage)
                            .error("VALIDATION_ERROR")
                            .timestamp(System.currentTimeMillis())
                            .build());
        }

        try {
            log.info("Signup with OTP request for email: {}", request.getEmail());

            // First verify the OTP before creating the account
            VerifyOtpRequest verifyRequest = VerifyOtpRequest.builder()
                    .email(request.getEmail())
                    .otp(request.getOtp())
                    .type("SIGNUP_VERIFICATION")
                    .build();

            // Use the non-consuming verification first
            OtpResponse otpVerification = otpService.verifyOtpForSignup(verifyRequest);

            if (!otpVerification.getSuccess()) {
                log.warn("OTP verification failed during signup: {}", otpVerification.getMessage());
                return ResponseEntity.badRequest()
                        .body(ApiResponse.<AuthResponse>builder()
                                .success(false)
                                .message(otpVerification.getMessage())
                                .error("OTP_VERIFICATION_FAILED")
                                .timestamp(System.currentTimeMillis())
                                .build());
            }

            // If OTP is valid, proceed with account creation
            AuthResponse response = authService.signupWithOtp(request);

            if (response == null) {
                log.error("AuthService returned null response for signup");
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(ApiResponse.<AuthResponse>builder()
                                .success(false)
                                .message("Account creation failed")
                                .error("AUTH_SERVICE_ERROR")
                                .timestamp(System.currentTimeMillis())
                                .build());
            }

            // Now consume the OTP after successful account creation
            otpService.verifyAndConsumeOtp(verifyRequest);

            return ResponseEntity.ok(ApiResponse.<AuthResponse>builder()
                    .success(true)
                    .message("Account created successfully")
                    .data(response)
                    .timestamp(System.currentTimeMillis())
                    .build());

        } catch (IllegalArgumentException e) {
            log.error("Invalid argument in signup with OTP: {}", e.getMessage());
            return ResponseEntity.badRequest()
                    .body(ApiResponse.<AuthResponse>builder()
                            .success(false)
                            .message("Invalid request data: " + e.getMessage())
                            .error("INVALID_ARGUMENT")
                            .timestamp(System.currentTimeMillis())
                            .build());
        } catch (Exception e) {
            log.error("Error in signup with OTP for email: {}", request.getEmail(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.<AuthResponse>builder()
                            .success(false)
                            .message("Failed to create account: " + e.getMessage())
                            .error("SIGNUP_ERROR")
                            .timestamp(System.currentTimeMillis())
                            .build());
        }
    }

    @GetMapping("/status/{email}")
    public ResponseEntity<ApiResponse<OtpStatusResponse>> getOtpStatus(@PathVariable String email) {
        try {
            log.info("Getting OTP status for email: {}", email);

            if (!isValidEmail(email)) {
                return ResponseEntity.badRequest()
                        .body(ApiResponse.<OtpStatusResponse>builder()
                                .success(false)
                                .message("Invalid email format")
                                .error("INVALID_EMAIL")
                                .timestamp(System.currentTimeMillis())
                                .build());
            }

            // Use the actual service method
            OTPService.OtpStatusResponse statusResponse = otpService.getOtpStatus(email);

            return ResponseEntity.ok(ApiResponse.<OtpStatusResponse>builder()
                    .success(true)
                    .message("OTP status retrieved")
                    .data(OtpStatusResponse.builder()
                            .email(statusResponse.getEmail())
                            .hasActiveOtp(statusResponse.isHasActiveOtp())
                            .attemptsRemaining(statusResponse.getAttemptsRemaining())
                            .nextAllowedTime(statusResponse.getNextAllowedTime())
                            .build())
                    .timestamp(System.currentTimeMillis())
                    .build());

        } catch (Exception e) {
            log.error("Error getting OTP status for email: {}", email, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.<OtpStatusResponse>builder()
                            .success(false)
                            .message("Failed to get OTP status")
                            .error("OTP_STATUS_ERROR")
                            .timestamp(System.currentTimeMillis())
                            .build());
        }
    }

    // Add debug endpoint to help troubleshoot
    @PostMapping("/debug/verify")
    public ResponseEntity<ApiResponse<Object>> debugVerifyOtp(
            @RequestBody VerifyOtpRequest request) {
        try {
            log.info("DEBUG: OTP verification for email: {}, otp: {}, type: {}",
                    request.getEmail(), request.getOtp(), request.getType());

            // Get current OTP status
            OTPService.OtpStatusResponse status = otpService.getOtpStatus(request.getEmail());

            // Try verification
            OtpResponse verification = otpService.verifyOtpForSignup(request);

            return ResponseEntity.ok(ApiResponse.builder()
                    .success(true)
                    .message("Debug info retrieved")
                    .data(new DebugInfo(status, verification, request))
                    .timestamp(System.currentTimeMillis())
                    .build());

        } catch (Exception e) {
            log.error("Debug verification error: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.builder()
                            .success(false)
                            .message("Debug failed: " + e.getMessage())
                            .error("DEBUG_ERROR")
                            .timestamp(System.currentTimeMillis())
                            .build());
        }
    }

    // ===== VALIDATION HELPER METHODS =====

    private boolean isValidOtpType(String type) {
        if (type == null) return false;
        try {
            OTPType.valueOf(type.toUpperCase());
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private boolean isValidEmail(String email) {
        if (email == null || email.trim().isEmpty()) return false;
        return email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    }

    // ===== EXCEPTION HANDLER =====

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiResponse<Object>> handleIllegalArgument(IllegalArgumentException e) {
        log.error("Illegal argument exception: {}", e.getMessage());
        return ResponseEntity.badRequest()
                .body(ApiResponse.builder()
                        .success(false)
                        .message("Invalid request: " + e.getMessage())
                        .error("INVALID_ARGUMENT")
                        .timestamp(System.currentTimeMillis())
                        .build());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Object>> handleGenericException(Exception e) {
        log.error("Unexpected error in OTP controller: ", e);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.builder()
                        .success(false)
                        .message("An unexpected error occurred")
                        .error("INTERNAL_SERVER_ERROR")
                        .timestamp(System.currentTimeMillis())
                        .build());
    }

    // ===== INNER CLASSES =====

    @Data
    @Builder
    public static class ApiResponse<T> {
        private boolean success;
        private String message;
        private T data;
        private String error;
        private long timestamp;
    }

    @Data
    @Builder
    public static class OtpStatusResponse {
        private String email;
        private boolean hasActiveOtp;
        private int attemptsRemaining;
        private Long nextAllowedTime;
    }

    @Data
    @Builder
    public static class DebugInfo {
        private OTPService.OtpStatusResponse status;
        private OtpResponse verification;
        private VerifyOtpRequest originalRequest;

        public DebugInfo(OTPService.OtpStatusResponse status, OtpResponse verification, VerifyOtpRequest request) {
            this.status = status;
            this.verification = verification;
            this.originalRequest = request;
        }
    }
}