package com.moveapp.movebackend.controller;

import com.moveapp.movebackend.model.dto.ApiResponse;
import com.moveapp.movebackend.model.dto.AuthenticationDto.*;
import com.moveapp.movebackend.model.dto.OTPdto.OtpResponse;
import com.moveapp.movebackend.model.dto.OTPdto.ResetPasswordRequest;
import com.moveapp.movebackend.model.dto.OTPdto.SignupWithOtpRequest;
import com.moveapp.movebackend.model.dto.OTPdto.VerifyOtpRequest;
import com.moveapp.movebackend.model.entities.User;
import com.moveapp.movebackend.repository.UserRepository;
import com.moveapp.movebackend.security.JwtTokenProvider;
import com.moveapp.movebackend.service.AuthServiceImpl;
import com.moveapp.movebackend.service.EmailService;
import com.moveapp.movebackend.exception.AuthenticationException;
import jakarta.validation.Valid;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = {"http://localhost:5173", "http://localhost:3000"})
public class AuthController {

    private final AuthServiceImpl authService;
    private final UserRepository userRepository;
    private final JwtTokenProvider tokenProvider;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    // ===== AUTHENTICATION ENDPOINTS =====

    @PostMapping("/signin")
    public ResponseEntity<ApiResponse<AuthResponse>> signin(@Valid @RequestBody AuthRequest authRequest) {
        try {
            log.info("User signin request for email: {}", authRequest.getEmail());
            AuthResponse response = authService.signin(authRequest);

            return ResponseEntity.ok(ApiResponse.<AuthResponse>success(response, "Sign in successful"));

        } catch (Exception e) {
            log.error("Error during signin for email: {}", authRequest.getEmail(), e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.<AuthResponse>error(e.getMessage(), "AUTHENTICATION_FAILED"));
        }
    }

    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<AuthResponse>> signup(@Valid @RequestBody SignupRequest signUpRequest) {
        try {
            log.info("User signup request for email: {}", signUpRequest.getEmail());
            AuthResponse response = authService.signup(signUpRequest);

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(ApiResponse.<AuthResponse>success(response, "Account created successfully"));

        } catch (AuthenticationException e) {
            log.error("Authentication error during signup for email: {}", signUpRequest.getEmail(), e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.<AuthResponse>error(e.getMessage(), "SIGNUP_FAILED"));
        } catch (Exception e) {
            log.error("Error during signup for email: {}", signUpRequest.getEmail(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.<AuthResponse>error("An unexpected error occurred", "INTERNAL_SERVER_ERROR"));
        }
    }

    @PostMapping("/signup/with-otp")
    public ResponseEntity<ApiResponse<AuthResponse>> signupWithOtp(@Valid @RequestBody SignupWithOtpRequest request) {
        try {
            log.info("User signup with OTP for email: {}", request.getEmail());
            AuthResponse response = authService.signupWithOtp(request);

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(ApiResponse.<AuthResponse>success(response, "Account created successfully with OTP verification"));

        } catch (AuthenticationException e) {
            log.error("Authentication error during signup with OTP for email: {}", request.getEmail(), e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.<AuthResponse>error(e.getMessage(), "SIGNUP_WITH_OTP_FAILED"));
        } catch (Exception e) {
            log.error("Error during signup with OTP for email: {}", request.getEmail(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.<AuthResponse>error("An unexpected error occurred", "INTERNAL_SERVER_ERROR"));
        }
    }

    // ===== OTP VERIFICATION ENDPOINTS =====

    @PostMapping("/otp/signup/send")
    public ResponseEntity<ApiResponse<OtpResponse>> sendSignupOtp(@Valid @RequestBody EmailRequest request) {
        try {
            log.info("Sending signup OTP for email: {}", request.getEmail());
            OtpResponse response = authService.sendSignupOtp(request.getEmail());

            HttpStatus status = response.getSuccess() ? HttpStatus.OK : HttpStatus.BAD_REQUEST;
            return ResponseEntity.status(status)
                    .body(ApiResponse.<OtpResponse>success(response, response.getMessage()));

        } catch (Exception e) {
            log.error("Error sending signup OTP for email: {}", request.getEmail(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.<OtpResponse>error("Failed to send signup OTP", "OTP_SEND_ERROR"));
        }
    }
    @PostMapping("/otp/signup/verify")
    public ResponseEntity<ApiResponse<OtpResponse>> verifySignupOtp(@Valid @RequestBody VerifyOtpRequest request) {
        try {
            log.info("Verifying signup OTP for email: {}", request.getEmail());

            // Force the type to be SIGNUP_VERIFICATION
            request.setType("SIGNUP_VERIFICATION");

            OtpResponse response = authService.verifySignupOtp(request.getEmail(), request.getOtp());

            HttpStatus status = response.getSuccess() ? HttpStatus.OK : HttpStatus.BAD_REQUEST;
            return ResponseEntity.status(status)
                    .body(ApiResponse.<OtpResponse>success(response, response.getMessage()));

        } catch (Exception e) {
            log.error("Error verifying signup OTP for email: {}", request.getEmail(), e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.<OtpResponse>error("Failed to verify signup OTP", "OTP_VERIFY_ERROR"));
        }
    }

    @PostMapping("/otp/password-reset/send")
    public ResponseEntity<ApiResponse<OtpResponse>> sendPasswordResetOtp(@Valid @RequestBody EmailRequest request) {
        try {
            log.info("Sending password reset OTP for email: {}", request.getEmail());
            OtpResponse response = authService.sendPasswordResetOtp(request.getEmail());

            HttpStatus status = response.getSuccess() ? HttpStatus.OK : HttpStatus.BAD_REQUEST;
            return ResponseEntity.status(status)
                    .body(ApiResponse.<OtpResponse>success(response, response.getMessage()));

        } catch (Exception e) {
            log.error("Error sending password reset OTP for email: {}", request.getEmail(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.<OtpResponse>error("Failed to send password reset OTP", "OTP_SEND_ERROR"));
        }
    }

    @PostMapping("/otp/password-reset/verify")
    public ResponseEntity<ApiResponse<OtpResponse>> verifyPasswordResetOtp(@Valid @RequestBody VerifyOtpRequest request) {
        try {
            log.info("Verifying password reset OTP for email: {}", request.getEmail());

            // Force the type to be PASSWORD_RESET
            request.setType("PASSWORD_RESET");

            OtpResponse response = authService.verifyPasswordResetOtp(request.getEmail(), request.getOtp());

            HttpStatus status = response.getSuccess() ? HttpStatus.OK : HttpStatus.BAD_REQUEST;
            return ResponseEntity.status(status)
                    .body(ApiResponse.<OtpResponse>success(response, response.getMessage()));

        } catch (Exception e) {
            log.error("Error verifying password reset OTP for email: {}", request.getEmail(), e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.<OtpResponse>error("Failed to verify password reset OTP", "OTP_VERIFY_ERROR"));
        }
    }
    // ===== PASSWORD RESET ENDPOINTS =====
    @PostMapping("/password/reset")
    public ResponseEntity<ApiResponse<OtpResponse>> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        try {
            log.info("Processing password reset for email: {}", request.getEmail());

            OtpResponse otpResponse = authService.resetPassword(request);

            HttpStatus status = otpResponse.getSuccess() ? HttpStatus.OK : HttpStatus.BAD_REQUEST;
            return ResponseEntity.status(status)
                    .body(ApiResponse.<OtpResponse>success(otpResponse, otpResponse.getMessage()));

        } catch (AuthenticationException e) {
            log.error("Authentication error during password reset for email: {}", request.getEmail(), e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.<OtpResponse>error(e.getMessage(), "AUTHENTICATION_ERROR"));
        } catch (Exception e) {
            log.error("Error during password reset for email: {}", request.getEmail(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.<OtpResponse>error("Password reset failed", "INTERNAL_SERVER_ERROR"));
        }
    }

    // ===== USER PROFILE ENDPOINTS =====

    @GetMapping("/me")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<ApiResponse<UserDto>> getCurrentUser(@AuthenticationPrincipal UserDetails userDetails) {
        try {
            log.info("Getting current user profile for: {}", userDetails.getUsername());
            User user = userRepository.findByEmail(userDetails.getUsername())
                    .orElseThrow(() -> new AuthenticationException("User not found"));

            UserDto userDto = UserDto.builder()
                    .id(user.getId())
                    .name(user.getName())
                    .email(user.getEmail())
                    .avatarUrl(user.getAvatarUrl())
                    .authProvider(user.getAuthProvider() != null ? user.getAuthProvider().name() : "LOCAL")
                    .emailVerified(user.getEmailVerified())
                    .providerId(user.getProviderId())
                    .createdAt(user.getCreatedAt())
                    .updatedAt(user.getUpdatedAt())
                    .build();

            return ResponseEntity.ok(ApiResponse.<UserDto>success(userDto, "User profile retrieved successfully"));

        } catch (Exception e) {
            log.error("Error getting current user", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.<UserDto>error("Error getting user profile", "PROFILE_FETCH_ERROR"));
        }
    }

    @PutMapping("/me")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<ApiResponse<UserDto>> updateCurrentUser(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody UpdateUserRequest request) {
        try {
            log.info("Updating user profile for: {}", userDetails.getUsername());
            UserDto updatedUser = authService.updateUserProfile(
                    userDetails.getUsername(),
                    request.getName(),
                    request.getAvatarUrl()
            );

            return ResponseEntity.ok(ApiResponse.<UserDto>success(updatedUser, "Profile updated successfully"));

        } catch (Exception e) {
            log.error("Error updating user profile", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.<UserDto>error("Error updating user profile", "PROFILE_UPDATE_ERROR"));
        }
    }

    // ===== TOKEN MANAGEMENT ENDPOINTS =====

    @PostMapping("/validate")
    public ResponseEntity<ApiResponse<UserDto>> validateToken(@RequestHeader("Authorization") String token) {
        try {
            String jwt = token.startsWith("Bearer ") ? token.substring(7) : token;

            if (tokenProvider.validateToken(jwt)) {
                String email = tokenProvider.getEmailFormatToken(jwt);
                User user = userRepository.findByEmail(email)
                        .orElseThrow(() -> new AuthenticationException("User not found"));

                UserDto userDto = UserDto.builder()
                        .id(user.getId())
                        .name(user.getName())
                        .email(user.getEmail())
                        .avatarUrl(user.getAvatarUrl())
                        .authProvider(user.getAuthProvider() != null ? user.getAuthProvider().name() : "LOCAL")
                        .emailVerified(user.getEmailVerified())
                        .providerId(user.getProviderId())
                        .createdAt(user.getCreatedAt())
                        .updatedAt(user.getUpdatedAt())
                        .build();

                return ResponseEntity.ok(ApiResponse.<UserDto>success(userDto, "Token is valid"));

            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(ApiResponse.<UserDto>error("Invalid token", "INVALID_TOKEN"));
            }
        } catch (Exception e) {
            log.error("Error validating token", e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.<UserDto>error("Token validation failed", "TOKEN_VALIDATION_ERROR"));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<AuthResponse>> refreshToken(@RequestHeader("Authorization") String token) {
        try {
            AuthResponse response = authService.refreshToken(token);

            return ResponseEntity.ok(ApiResponse.<AuthResponse>success(response, "Token refreshed successfully"));

        } catch (Exception e) {
            log.error("Error during token refresh", e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.<AuthResponse>error("Token refresh failed", "TOKEN_REFRESH_ERROR"));
        }
    }

    @PostMapping("/signout")
    public ResponseEntity<ApiResponse<Void>> signout(@RequestHeader(value = "Authorization", required = false) String token) {
        try {
            if (token != null) {
                authService.signout(token);
            }
            return ResponseEntity.ok(ApiResponse.<Void>success("Signed out successfully"));
        } catch (Exception e) {
            log.error("Error during signout", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.<Void>error("Signout failed", "SIGNOUT_ERROR"));
        }
    }

    // ===== TEST ENDPOINT =====

    @GetMapping("/test")
    public ResponseEntity<ApiResponse<String>> test() {
        return ResponseEntity.ok(ApiResponse.<String>success("Auth service operational", "Auth controller is working!"));
    }

    // ===== INNER CLASSES =====

    @Data
    public static class UpdateUserRequest {
        private String name;
        private String avatarUrl;
    }

    @Data
    public static class EmailRequest {
        private String email;
    }
}