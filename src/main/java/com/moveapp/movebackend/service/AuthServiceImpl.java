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
import java.util.concurrent.TimeoutException;

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

    @Override
    public OtpResponse sendSignupOtp(String email) {
        log.info("Sending signup OTP to email: {}", email);

        try {
            String normalizedEmail = email.toLowerCase().trim();

            // Check if email already exists
            if (userRepository.existsByEmail(normalizedEmail)) {
                log.warn("Signup OTP request for existing email: {}", normalizedEmail);
                return OtpResponse.builder()
                        .success(false)
                        .message("Email address already registered.")
                        .build();
            }

            // Create OTP request
            SendOtpRequest request = SendOtpRequest.builder()
                    .email(normalizedEmail)
                    .type("SIGNUP_VERIFICATION")
                    .build();

            // Send OTP via OTP service with timeout handling
            OtpResponse response;
            try {
                response = otpService.sendOtp(request);
            } catch (Exception e) {
                log.error("Exception while sending OTP: {}", e.getMessage(), e);
                
                // Check if it's a timeout exception
                if (e instanceof TimeoutException || 
                    (e.getMessage() != null && e.getMessage().toLowerCase().contains("timeout"))) {
                    log.warn("Email sending timeout for signup: {}", normalizedEmail);
                    return OtpResponse.builder()
                            .success(false)
                            .message("Email sending timeout. The OTP may still arrive. Please wait a moment and try again if needed.")
                            .build();
                }
                
                // Generic error
                return OtpResponse.builder()
                        .success(false)
                        .message("Failed to send OTP. Please try again.")
                        .build();
            }

            // Handle various failure scenarios
            if (!response.getSuccess()) {
                String message = response.getMessage();
                
                if (message != null && message.toLowerCase().contains("timeout")) {
                    log.warn("Email sending timeout for signup: {}", normalizedEmail);
                    return OtpResponse.builder()
                            .success(false)
                            .message("Email sending timeout. Please wait a moment and try again.")
                            .build();
                }
                
                if (message != null && message.contains("Failed to send")) {
                    log.warn("Email sending failed for signup: {}", normalizedEmail);
                    return OtpResponse.builder()
                            .success(false)
                            .message("Failed to send verification email. Please check your email address and try again.")
                            .build();
                }
                
                log.warn("Signup OTP failed for: {} - {}", normalizedEmail, message);
                return response;
            }

            log.info("Signup OTP sent successfully to: {}", normalizedEmail);
            return response;

        } catch (Exception e) {
            log.error("Error sending signup OTP to: {}", email, e);
            return OtpResponse.builder()
                    .success(false)
                    .message("Failed to send OTP. Please try again.")
                    .build();
        }
    }

    @Override
    public OtpResponse verifySignupOtp(String email, String otp) {
        log.info("Verifying signup OTP for email: {}", email);

        try {
            String normalizedEmail = email.toLowerCase().trim();
            String normalizedOtp = otp.trim();
            
            // Enhanced debug logging
            log.debug("Normalized email: {}", normalizedEmail);
            log.debug("OTP length: {}", normalizedOtp.length());
            log.debug("OTP value: {}", normalizedOtp);

            if (userRepository.existsByEmail(normalizedEmail)) {
                log.warn("Signup OTP verification for existing email: {}", normalizedEmail);
                return OtpResponse.builder()
                        .success(false)
                        .message("Email address already registered. Please login instead.")
                        .build();
            }

            VerifyOtpRequest otpRequest = VerifyOtpRequest.builder()
                    .email(normalizedEmail)
                    .otp(normalizedOtp)
                    .type("SIGNUP_VERIFICATION")
                    .build();

            log.debug("Calling OTP service with request: email={}, type={}", 
                      normalizedEmail, otpRequest.getType());

            OtpResponse response = otpService.verifyOtpWithoutConsuming(otpRequest);

            log.debug("OTP service response: success={}, message={}", 
                      response.getSuccess(), response.getMessage());

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

    @Override
    public AuthResponse signupWithOtp(SignupWithOtpRequest request) {
        log.info("Processing signup with OTP for email: {}", request.getEmail());

        try {
            String normalizedEmail = request.getEmail().toLowerCase().trim();

            if (userRepository.existsByEmail(normalizedEmail)) {
                log.warn("Signup attempt with existing email: {}", normalizedEmail);
                throw new AuthenticationException("Email address already in use.");
            }

            if (request.getOtp() != null && !request.getOtp().trim().isEmpty()) {
                VerifyOtpRequest otpRequest = VerifyOtpRequest.builder()
                        .email(normalizedEmail)
                        .otp(request.getOtp().trim())
                        .type("SIGNUP_VERIFICATION")
                        .build();

                log.debug("Verifying OTP before signup completion");
                OtpResponse otpResponse = otpService.verifyOtp(otpRequest);

                if (!otpResponse.getSuccess()) {
                    log.warn("OTP verification failed during signup: {}", otpResponse.getMessage());
                    throw new AuthenticationException("OTP verification failed: " + otpResponse.getMessage());
                }
                
                log.info("OTP verified successfully, proceeding with user creation");
            } else {
                log.warn("No OTP provided for signup, proceeding anyway due to email service issues");
            }

            User user = User.builder()
                    .name(request.getName().trim())
                    .email(normalizedEmail)
                    .password(passwordEncoder.encode(request.getPassword()))
                    .authProvider(AuthProvider.LOCAL)
                    .emailVerified(true)
                    .build();

            log.debug("Saving new user with email: {}", user.getEmail());
            User savedUser = userRepository.save(user);

            // Send welcome email asynchronously (non-blocking)
            try {
                emailService.sendWelcomeEmail(savedUser.getEmail(), savedUser.getName());
                log.info("Welcome email sent to: {}", savedUser.getEmail());
            } catch (Exception e) {
                log.error("Failed to send welcome email to: {}", savedUser.getEmail(), e);
                // Don't fail the signup if welcome email fails
            }

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

    @Override
    public AuthResponse signin(AuthRequest authRequest) {
        log.info("Processing signin for email: {}", authRequest.getEmail());

        try {
            String normalizedEmail = authRequest.getEmail().toLowerCase().trim();

            User user = userRepository.findByEmail(normalizedEmail)
                    .orElseThrow(() -> new AuthenticationException("No account found with this email address"));

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

    @Override
    public OtpResponse sendPasswordResetOtp(String email) {
        log.info("Sending password reset OTP to email: {}", email);

        try {
            String normalizedEmail = email.toLowerCase().trim();

            if (!userRepository.existsByEmail(normalizedEmail)) {
                // Return success message even if user doesn't exist (security best practice)
                return OtpResponse.builder()
                        .success(true)
                        .message("If this email is registered, you will receive a reset code shortly.")
                        .build();
            }

            SendOtpRequest request = SendOtpRequest.builder()
                    .email(normalizedEmail)
                    .type("PASSWORD_RESET")
                    .build();

            OtpResponse response;
            try {
                response = otpService.sendOtp(request);
            } catch (Exception e) {
                log.error("Exception while sending password reset OTP: {}", e.getMessage(), e);
                
                // Check for timeout
                if (e instanceof TimeoutException || 
                    (e.getMessage() != null && e.getMessage().toLowerCase().contains("timeout"))) {
                    return OtpResponse.builder()
                            .success(false)
                            .message("Email sending timeout. Please try again in a moment.")
                            .build();
                }
                
                return OtpResponse.builder()
                        .success(true)
                        .message("If this email is registered, you will receive a reset code shortly.")
                        .build();
            }

            // Handle timeout in response
            if (!response.getSuccess() && response.getMessage() != null &&
                    (response.getMessage().toLowerCase().contains("timeout") ||
                     response.getMessage().contains("Failed to send"))) {
                log.warn("Email sending failed for password reset: {}", normalizedEmail);
                return OtpResponse.builder()
                        .success(false)
                        .message("Email service temporarily unavailable. Please try again in a moment.")
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

    @Override
    public OtpResponse verifyPasswordResetOtp(String email, String otp) {
        log.info("Verifying password reset OTP for email: {}", email);

        try {
            String normalizedEmail = email.toLowerCase().trim();
            String normalizedOtp = otp.trim();
            
            // Enhanced debug logging
            log.debug("Normalized email: {}", normalizedEmail);
            log.debug("OTP length: {}", normalizedOtp.length());
            log.debug("OTP value: {}", normalizedOtp);

            User user = userRepository.findByEmail(normalizedEmail)
                    .orElseThrow(() -> {
                        log.error("User not found for email: {}", normalizedEmail);
                        return new AuthenticationException("User not found");
                    });

            VerifyOtpRequest otpRequest = VerifyOtpRequest.builder()
                    .email(normalizedEmail)
                    .otp(normalizedOtp)
                    .type("PASSWORD_RESET")
                    .build();

            log.debug("Calling OTP service with request: email={}, type={}", 
                      normalizedEmail, otpRequest.getType());

            OtpResponse otpResponse = otpService.verifyOtpWithoutConsuming(otpRequest);

            log.debug("OTP service response: success={}, message={}", 
                      otpResponse.getSuccess(), otpResponse.getMessage());

            if (otpResponse.getSuccess()) {
                log.info("Password reset OTP verified successfully for user: {}", normalizedEmail);
            } else {
                log.warn("Password reset OTP verification failed: {}", otpResponse.getMessage());
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

    @Override
    public OtpResponse resetPassword(ResetPasswordRequest request) {
        log.info("Processing password reset for email: {}", request.getEmail());

        try {
            String normalizedEmail = request.getEmail().toLowerCase().trim();

            User user = userRepository.findByEmail(normalizedEmail)
                    .orElseThrow(() -> new AuthenticationException("User not found"));

            VerifyOtpRequest otpRequest = VerifyOtpRequest.builder()
                    .email(normalizedEmail)
                    .otp(request.getOtp().trim())
                    .type("PASSWORD_RESET")
                    .build();

            log.debug("Verifying OTP for password reset");
            OtpResponse otpResponse = otpService.verifyOtp(otpRequest);

            if (!otpResponse.getSuccess()) {
                throw new AuthenticationException("OTP verification failed: " + otpResponse.getMessage());
            }

            user.setPassword(passwordEncoder.encode(request.getNewPassword()));
            userRepository.save(user);

            // Send confirmation email asynchronously
            try {
                emailService.sendPasswordResetConfirmationEmail(user.getEmail());
                log.info("Password reset confirmation email sent to: {}", user.getEmail());
            } catch (Exception e) {
                log.error("Failed to send password reset confirmation email", e);
                // Don't fail password reset if confirmation email fails
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
        log.debug("verifyOtp called with type: {}, email: {}", 
                  request.getType(), request.getEmail());
        
        if ("SIGNUP_VERIFICATION".equals(request.getType())) {
            return verifySignupOtp(request.getEmail(), request.getOtp());
        } else if ("PASSWORD_RESET".equals(request.getType())) {
            return verifyPasswordResetOtp(request.getEmail(), request.getOtp());
        } else {
            // For any other type, delegate to OTP service
            log.debug("Delegating to otpService for type: {}", request.getType());
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
