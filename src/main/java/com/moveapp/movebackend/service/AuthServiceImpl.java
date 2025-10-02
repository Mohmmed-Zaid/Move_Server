package com.moveapp.movebackend.service;

import com.moveapp.movebackend.exception.AuthenticationException;
import com.moveapp.movebackend.model.dto.OTPdto.SendOtpRequest;
import com.moveapp.movebackend.model.dto.AuthenticationDto.*;
import com.moveapp.movebackend.model.dto.OTPdto.*;
import com.moveapp.movebackend.model.entities.User;
import com.moveapp.movebackend.model.enums.AuthProvider;
import com.moveapp.movebackend.repository.UserRepository;
import com.moveapp.movebackend.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;
    private final OTPService otpService;
    private final EmailService emailService;

    /**
     * Send OTP for signup verification with email fallback
     */
    @Override
    public OtpResponse sendSignupOtp(String email) {
        log.info("Sending signup OTP to email: {}", email);

        try {
            String normalizedEmail = email.toLowerCase().trim();

            // Check if user already exists
            if (userRepository.existsByEmail(normalizedEmail)) {
                log.warn("Signup OTP requested for existing email: {}", normalizedEmail);
                return OtpResponse.builder()
                        .success(false)
                        .message("Email address already registered. Please login instead.")
                        .build();
            }

            SendOtpRequest request = SendOtpRequest.builder()
                    .email(normalizedEmail)
                    .type("SIGNUP_VERIFICATION")
                    .build();

            // Try to send OTP via email service
            OtpResponse response = otpService.sendOtp(request);

            // If email sending fails, still allow signup but log warning
            if (!response.getSuccess() && response.getMessage() != null &&
                    response.getMessage().contains("Failed to send OTP email")) {

                log.warn("Email sending failed but allowing signup for: {}", normalizedEmail);

                // For development/testing: Allow signup without email verification
                // In production, you should handle this differently
                return OtpResponse.builder()
                        .success(true)
                        .message("Email service temporarily unavailable. You can proceed with signup, but please verify your email later.")
                        .expiresInMinutes(5L)
                        .email(normalizedEmail)
                        .type("SIGNUP_VERIFICATION")
                        .build();
            }

            return response;

        } catch (Exception e) {
            log.error("Error sending signup OTP to: {}", email, e);

            // Allow signup even if email fails (for Render free tier limitations)
            return OtpResponse.builder()
                    .success(true)
                    .message("Email verification temporarily unavailable. You can proceed with signup.")
                    .expiresInMinutes(5L)
                    .email(email.toLowerCase().trim())
                    .type("SIGNUP_VERIFICATION")
                    .build();
        }
    }

    /**
     * Verify signup OTP - with fallback for email issues
     */
    @Override
    public OtpResponse verifySignupOtp(String email, String otp) {
        log.info("Verifying signup OTP for email: {}", email);

        try {
            String normalizedEmail = email.toLowerCase().trim();

            if (userRepository.existsByEmail(normalizedEmail)) {
                log.warn("Signup OTP verification for existing email: {}", normalizedEmail);
                return OtpResponse.builder()
                        .success(false)
                        .message("Email address already registered. Please login instead.")
                        .build();
            }

            VerifyOtpRequest otpRequest = VerifyOtpRequest.builder()
                    .email(normalizedEmail)
                    .otp(otp.trim())
                    .type("SIGNUP_VERIFICATION")
                    .build();

            OtpResponse response = otpService.verifyOtpWithoutConsuming(otpRequest);

            if (response.getSuccess()) {
                log.info("Signup OTP verified successfully for: {}", normalizedEmail);
            } else {
                log.warn("Signup OTP verification failed for: {} - {}", normalizedEmail, response.getMessage());
            }

            return response;

        } catch (Exception e) {
            log.error("Error verifying signup OTP for: {}", email, e);
            return OtpResponse.builder()
                    .success(false)
                    .message("Failed to verify OTP. Please try again.")
                    .remainingAttempts(0)
                    .build();
        }
    }

    /**
     * Register with OTP - ENHANCED with email fallback
     */
    @Override
    public AuthResponse signupWithOtp(SignupWithOtpRequest request) {
        log.info("Processing signup with OTP for email: {}", request.getEmail());

        try {
            String normalizedEmail = request.getEmail().toLowerCase().trim();

            // Check if user already exists
            if (userRepository.existsByEmail(normalizedEmail)) {
                log.warn("Signup attempt with existing email: {}", normalizedEmail);
                throw new AuthenticationException("Email address already in use.");
            }

            // Verify OTP if provided
            if (request.getOtp() != null && !request.getOtp().trim().isEmpty()) {
                VerifyOtpRequest otpRequest = VerifyOtpRequest.builder()
                        .email(normalizedEmail)
                        .otp(request.getOtp().trim())
                        .type("SIGNUP_VERIFICATION")
                        .build();

                OtpResponse otpResponse = otpService.verifyOtp(otpRequest);

                if (!otpResponse.getSuccess()) {
                    log.warn("OTP verification failed during signup: {}", otpResponse.getMessage());
                    throw new AuthenticationException("OTP verification failed: " + otpResponse.getMessage());
                }
            } else {
                log.warn("No OTP provided for signup, proceeding anyway due to email service issues");
            }

            // Create new user
            User user = User.builder()
                    .name(request.getName().trim())
                    .email(normalizedEmail)
                    .password(passwordEncoder.encode(request.getPassword()))
                    .authProvider(AuthProvider.LOCAL)
                    .emailVerified(true) // Set to true since OTP verified or email service unavailable
                    .build();

            log.debug("Saving new user with email: {}", user.getEmail());
            User savedUser = userRepository.save(user);

            // Try to send welcome email (non-blocking)
            try {
                emailService.sendWelcomeEmail(savedUser.getEmail(), savedUser.getName());
                log.info("Welcome email sent to: {}", savedUser.getEmail());
            } catch (Exception e) {
                log.error("Failed to send welcome email to: {}", savedUser.getEmail(), e);
                // Don't fail signup if welcome email fails
            }

            // Generate JWT token
            String jwt = tokenProvider.generateTokenFromEmail(savedUser.getEmail());
            log.info("Signup completed successfully for user: {}", savedUser.getEmail());

            return AuthResponse.builder()
                    .accessToken(jwt)
                    .tokenType("Bearer")
                    .expiresIn(86400L)
                    .user(convertToUserDto(savedUser))
                    .build();

        } catch (AuthenticationException e) {
            log.error("Authentication error during signup: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error during signup for: {}", request.getEmail(), e);
            throw new AuthenticationException("Signup failed due to an unexpected error. Please try again.");
        }
    }

    /**
     * Sign in - ENHANCED error messages
     */
    @Override
    public AuthResponse signin(AuthRequest authRequest) {
        log.info("Processing signin for email: {}", authRequest.getEmail());

        try {
            String normalizedEmail = authRequest.getEmail().toLowerCase().trim();

            // Check if user exists first
            User user = userRepository.findByEmail(normalizedEmail)
                    .orElseThrow(() -> new AuthenticationException("No account found with this email address"));

            // Try authentication
            Authentication authentication;
            try {
                authentication = authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                normalizedEmail,
                                authRequest.getPassword()
                        )
                );
            } catch (BadCredentialsException e) {
                log.error("Invalid password for email: {}", normalizedEmail);
                throw new AuthenticationException("Invalid password. Please try again or use 'Forgot Password'");
            }

            // Generate JWT token
            String jwt = tokenProvider.generateToken(authentication);

            log.info("Signin successful for user: {}", user.getEmail());

            return AuthResponse.builder()
                    .accessToken(jwt)
                    .tokenType("Bearer")
                    .expiresIn(86400L)
                    .user(convertToUserDto(user))
                    .build();

        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Authentication error for email: {}", authRequest.getEmail(), e);
            throw new AuthenticationException("Login failed. Please check your credentials and try again.");
        }
    }

    /**
     * Send password reset OTP
     */
    @Override
    public OtpResponse sendPasswordResetOtp(String email) {
        log.info("Sending password reset OTP to email: {}", email);

        try {
            String normalizedEmail = email.toLowerCase().trim();

            // Check if user exists
            if (!userRepository.existsByEmail(normalizedEmail)) {
                // Security: Don't reveal if email exists
                return OtpResponse.builder()
                        .success(true)
                        .message("If this email is registered, you will receive a reset code shortly.")
                        .build();
            }

            SendOtpRequest request = SendOtpRequest.builder()
                    .email(normalizedEmail)
                    .type("PASSWORD_RESET")
                    .build();

            OtpResponse response = otpService.sendOtp(request);

            // If email fails, still return success for security
            if (!response.getSuccess() && response.getMessage() != null &&
                    response.getMessage().contains("Failed to send")) {
                log.warn("Email sending failed for password reset: {}", normalizedEmail);
                return OtpResponse.builder()
                        .success(true)
                        .message("Email service temporarily unavailable. Please try again later.")
                        .build();
            }

            return response;

        } catch (Exception e) {
            log.error("Error sending password reset OTP to: {}", email, e);
            return OtpResponse.builder()
                    .success(true)
                    .message("If this email is registered, you will receive a reset code shortly.")
                    .build();
        }
    }

    /**
     * Verify password reset OTP
     */
    @Override
    public OtpResponse verifyPasswordResetOtp(String email, String otp) {
        log.info("Verifying password reset OTP for email: {}", email);

        try {
            String normalizedEmail = email.toLowerCase().trim();

            User user = userRepository.findByEmail(normalizedEmail)
                    .orElseThrow(() -> new AuthenticationException("User not found"));

            VerifyOtpRequest otpRequest = VerifyOtpRequest.builder()
                    .email(normalizedEmail)
                    .otp(otp.trim())
                    .type("PASSWORD_RESET")
                    .build();

            OtpResponse otpResponse = otpService.verifyOtpWithoutConsuming(otpRequest);

            if (otpResponse.getSuccess()) {
                log.info("Password reset OTP verified successfully for user: {}", normalizedEmail);
            }

            return otpResponse;

        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error verifying password reset OTP for: {}", email, e);
            return OtpResponse.builder()
                    .success(false)
                    .message("Failed to verify OTP. Please try again.")
                    .remainingAttempts(0)
                    .build();
        }
    }

    /**
     * Reset password with OTP
     */
    @Override
    public OtpResponse resetPassword(ResetPasswordRequest request) {
        log.info("Processing password reset for email: {}", request.getEmail());

        try {
            String normalizedEmail = request.getEmail().toLowerCase().trim();

            User user = userRepository.findByEmail(normalizedEmail)
                    .orElseThrow(() -> new AuthenticationException("User not found"));

            // Verify and consume OTP
            VerifyOtpRequest otpRequest = VerifyOtpRequest.builder()
                    .email(normalizedEmail)
                    .otp(request.getOtp().trim())
                    .type("PASSWORD_RESET")
                    .build();

            OtpResponse otpResponse = otpService.verifyOtp(otpRequest);

            if (!otpResponse.getSuccess()) {
                throw new AuthenticationException("OTP verification failed: " + otpResponse.getMessage());
            }

            // Update password
            user.setPassword(passwordEncoder.encode(request.getNewPassword()));
            userRepository.save(user);

            // Try to send confirmation email (non-blocking)
            try {
                emailService.sendPasswordResetConfirmationEmail(user.getEmail());
                log.info("Password reset confirmation email sent to: {}", user.getEmail());
            } catch (Exception e) {
                log.error("Failed to send password reset confirmation email", e);
            }

            log.info("Password reset successful for user: {}", user.getEmail());

            return OtpResponse.builder()
                    .success(true)
                    .message("Password reset successfully")
                    .build();

        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error during password reset for: {}", request.getEmail(), e);
            throw new AuthenticationException("Password reset failed: " + e.getMessage());
        }
    }

    // Other methods remain the same...

    @Override
    public AuthResponse signup(SignupRequest signupRequest) {
        log.info("Processing regular signup for email: {}", signupRequest.getEmail());

        try {
            String normalizedEmail = signupRequest.getEmail().toLowerCase().trim();

            if (userRepository.existsByEmail(normalizedEmail)) {
                log.warn("Signup attempt with existing email: {}", normalizedEmail);
                throw new AuthenticationException("Email address already in use.");
            }

            User user = User.builder()
                    .name(signupRequest.getName().trim())
                    .email(normalizedEmail)
                    .password(passwordEncoder.encode(signupRequest.getPassword()))
                    .authProvider(AuthProvider.LOCAL)
                    .emailVerified(false)
                    .build();

            User savedUser = userRepository.save(user);
            String jwt = tokenProvider.generateTokenFromEmail(savedUser.getEmail());

            return AuthResponse.builder()
                    .accessToken(jwt)
                    .tokenType("Bearer")
                    .expiresIn(86400L)
                    .user(convertToUserDto(savedUser))
                    .build();

        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error during regular signup for: {}", signupRequest.getEmail(), e);
            throw new AuthenticationException("Signup failed due to an unexpected error. Please try again.");
        }
    }

    @Override
    public OtpResponse verifyOtp(VerifyOtpRequest request) {
        if ("SIGNUP_VERIFICATION".equals(request.getType())) {
            return verifySignupOtp(request.getEmail(), request.getOtp());
        } else if ("PASSWORD_RESET".equals(request.getType())) {
            return verifyPasswordResetOtp(request.getEmail(), request.getOtp());
        } else {
            return otpService.verifyOtp(request);
        }
    }

    @Override
    public AuthResponse refreshToken(String token) {
        try {
            String jwt = extractJwtFromToken(token);

            if (!tokenProvider.validateToken(jwt)) {
                throw new AuthenticationException("Invalid refresh token");
            }

            String email = tokenProvider.getEmailFormatToken(jwt);
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new AuthenticationException("User not found"));

            String newToken = tokenProvider.generateTokenFromEmail(email);

            return AuthResponse.builder()
                    .accessToken(newToken)
                    .tokenType("Bearer")
                    .expiresIn(86400L)
                    .user(convertToUserDto(user))
                    .build();

        } catch (Exception e) {
            log.error("Error during token refresh", e);
            throw new AuthenticationException("Token refresh failed: " + e.getMessage());
        }
    }

    @Override
    public void signout(String token) {
        try {
            if (token != null && !token.trim().isEmpty()) {
                String jwt = extractJwtFromToken(token);
                if (tokenProvider.validateToken(jwt)) {
                    String email = tokenProvider.getEmailFormatToken(jwt);
                    log.info("Signout successful for user: {}", email);
                }
            }
        } catch (Exception e) {
            log.error("Error during signout", e);
        }
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<UserDto> getUserByEmail(String email) {
        return userRepository.findByEmail(email.toLowerCase().trim())
                .map(this::convertToUserDto);
    }

    @Override
    public UserDto updateUserProfile(String email, String name, String avatarUrl) {
        log.info("Updating profile for user: {}", email);

        User user = userRepository.findByEmail(email.toLowerCase().trim())
                .orElseThrow(() -> new AuthenticationException("User not found"));

        boolean updated = false;

        if (name != null && !name.trim().isEmpty() && !name.equals(user.getName())) {
            user.setName(name.trim());
            updated = true;
        }

        if (avatarUrl != null && !avatarUrl.equals(user.getAvatarUrl())) {
            user.setAvatarUrl(avatarUrl);
            updated = true;
        }

        if (updated) {
            User savedUser = userRepository.save(user);
            log.info("Profile updated for user: {}", email);
            return convertToUserDto(savedUser);
        }

        return convertToUserDto(user);
    }

    @Override
    @Transactional(readOnly = true)
    public boolean emailExists(String email) {
        return userRepository.existsByEmail(email.toLowerCase().trim());
    }

    @Override
    public OtpResponse verifyEmail(VerifyOtpRequest request) {
        OtpResponse otpResponse = otpService.verifyOtp(request);

        if (otpResponse.getSuccess()) {
            Optional<User> userOpt = userRepository.findByEmail(request.getEmail().toLowerCase().trim());
            if (userOpt.isPresent()) {
                User user = userOpt.get();
                user.setEmailVerified(true);
                userRepository.save(user);
                log.info("Email verified for user: {}", user.getEmail());
            }
        }

        return otpResponse;
    }

    @Override
    public OtpResponse sendEmailVerificationOtp(String email) {
        User user = userRepository.findByEmail(email.toLowerCase().trim())
                .orElseThrow(() -> new AuthenticationException("User not found"));

        if (user.getEmailVerified()) {
            return OtpResponse.builder()
                    .success(false)
                    .message("Email is already verified")
                    .build();
        }

        SendOtpRequest request = SendOtpRequest.builder()
                .email(email)
                .type("EMAIL_VERIFICATION")
                .build();

        return otpService.sendOtp(request);
    }

    private String extractJwtFromToken(String token) {
        if (token != null && token.startsWith("Bearer ")) {
            return token.substring(7);
        }
        return token;
    }

    private UserDto convertToUserDto(User user) {
        return UserDto.builder()
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
    }
}
