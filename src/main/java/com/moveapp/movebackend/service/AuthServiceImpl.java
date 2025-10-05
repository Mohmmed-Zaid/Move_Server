package com.moveapp.movebackend.service;

import com.moveapp.movebackend.exception.AuthenticationException;
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

    @Override
    public OtpResponse sendSignupOtp(String email) {
        log.info("=== SEND SIGNUP OTP ===");
        log.info("Email: {}", email);

        try {
            String normalizedEmail = email.toLowerCase().trim();

            if (userRepository.existsByEmail(normalizedEmail)) {
                log.warn("Email already exists: {}", normalizedEmail);
                return OtpResponse.builder()
                        .success(false)
                        .message("Email address already registered.")
                        .build();
            }

            SendOtpRequest request = SendOtpRequest.builder()
                    .email(normalizedEmail)
                    .type("SIGNUP_VERIFICATION")
                    .build();

            OtpResponse response = otpService.sendOtp(request);
            log.info("OTP send result: {}", response.getSuccess());
            
            return response;

        } catch (Exception e) {
            log.error("Error sending signup OTP: {}", e.getMessage(), e);
            return OtpResponse.builder()
                    .success(false)
                    .message("Failed to send OTP. Please try again.")
                    .build();
        }
    }

    @Override
    public OtpResponse verifySignupOtp(String email, String otp) {
        log.info("=== VERIFY SIGNUP OTP (NON-CONSUMING) ===");
        log.info("Email: {}, OTP: '{}'", email, otp);

        try {
            String normalizedEmail = email.toLowerCase().trim();
            String cleanOtp = otp.trim().replaceAll("\\s+", "");
            
            log.info("Cleaned - Email: '{}', OTP: '{}' (length: {})", 
                     normalizedEmail, cleanOtp, cleanOtp.length());

            if (userRepository.existsByEmail(normalizedEmail)) {
                return OtpResponse.builder()
                        .success(false)
                        .message("Email address already registered.")
                        .build();
            }

            VerifyOtpRequest otpRequest = VerifyOtpRequest.builder()
                    .email(normalizedEmail)
                    .otp(cleanOtp)
                    .type("SIGNUP_VERIFICATION")
                    .build();

            OtpResponse response = otpService.verifyOtpWithoutConsuming(otpRequest);
            log.info("Verification result: {}", response.getSuccess());

            return response;

        } catch (Exception e) {
            log.error("Error verifying signup OTP: {}", e.getMessage(), e);
            return OtpResponse.builder()
                    .success(false)
                    .message("Failed to verify OTP. Please try again.")
                    .remainingAttempts(0)
                    .build();
        }
    }

    @Override
    public AuthResponse signupWithOtp(SignupWithOtpRequest request) {
        log.info("=== SIGNUP WITH OTP ===");
        log.info("Email: {}", request.getEmail());

        try {
            String normalizedEmail = request.getEmail().toLowerCase().trim();
            String cleanOtp = request.getOtp().trim().replaceAll("\\s+", "");

            log.info("Processing signup - Email: '{}', OTP: '{}' (length: {})", 
                     normalizedEmail, cleanOtp, cleanOtp.length());

            // Check if email already exists
            if (userRepository.existsByEmail(normalizedEmail)) {
                log.warn("Email already exists: {}", normalizedEmail);
                throw new AuthenticationException("Email address already in use.");
            }

            // Verify AND consume the OTP
            VerifyOtpRequest otpRequest = VerifyOtpRequest.builder()
                    .email(normalizedEmail)
                    .otp(cleanOtp)
                    .type("SIGNUP_VERIFICATION")
                    .build();

            log.info("Verifying OTP before account creation...");
            OtpResponse otpResponse = otpService.verifyOtp(otpRequest);
            log.info("OTP verification result: {}, Message: {}", 
                     otpResponse.getSuccess(), otpResponse.getMessage());

            if (!otpResponse.getSuccess()) {
                log.warn("OTP verification failed: {}", otpResponse.getMessage());
                throw new AuthenticationException("OTP verification failed: " + otpResponse.getMessage());
            }

            log.info("✓ OTP verified successfully, creating user account...");

            // Create user
            User user = User.builder()
                    .name(request.getName().trim())
                    .email(normalizedEmail)
                    .password(passwordEncoder.encode(request.getPassword()))
                    .authProvider(AuthProvider.LOCAL)
                    .emailVerified(true)
                    .build();

            User savedUser = userRepository.save(user);
            log.info("✓ User created successfully - ID: {}, Email: {}", 
                     savedUser.getId(), savedUser.getEmail());

            // Send welcome email (non-blocking)
            try {
                emailService.sendWelcomeEmail(savedUser.getEmail(), savedUser.getName());
            } catch (Exception e) {
                log.error("Failed to send welcome email (non-critical): {}", e.getMessage());
            }

            // Generate JWT
            String jwt = tokenProvider.generateTokenFromEmail(savedUser.getEmail());

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
            log.error("Unexpected error during signup: {}", e.getMessage(), e);
            throw new AuthenticationException("Signup failed: " + e.getMessage());
        }
    }

    @Override
    public AuthResponse signin(AuthRequest authRequest) {
        log.info("=== SIGNIN ===");
        log.info("Email: {}", authRequest.getEmail());

        try {
            String normalizedEmail = authRequest.getEmail().toLowerCase().trim();

            User user = userRepository.findByEmail(normalizedEmail)
                    .orElseThrow(() -> new AuthenticationException("No account found with this email"));

            Authentication authentication;
            try {
                authentication = authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                normalizedEmail,
                                authRequest.getPassword()
                        )
                );
            } catch (BadCredentialsException e) {
                throw new AuthenticationException("Invalid password");
            }

            String jwt = tokenProvider.generateToken(authentication);

            log.info("✓ Signin successful for user: {}", user.getEmail());

            return AuthResponse.builder()
                    .accessToken(jwt)
                    .tokenType("Bearer")
                    .expiresIn(86400L)
                    .user(convertToUserDto(user))
                    .build();

        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Signin error: {}", e.getMessage(), e);
            throw new AuthenticationException("Login failed: " + e.getMessage());
        }
    }

    @Override
    public OtpResponse sendPasswordResetOtp(String email) {
        log.info("=== SEND PASSWORD RESET OTP ===");
        log.info("Email: {}", email);

        try {
            String normalizedEmail = email.toLowerCase().trim();

            if (!userRepository.existsByEmail(normalizedEmail)) {
                // Security: Don't reveal if email exists
                return OtpResponse.builder()
                        .success(true)
                        .message("If this email is registered, you will receive a reset code.")
                        .build();
            }

            SendOtpRequest request = SendOtpRequest.builder()
                    .email(normalizedEmail)
                    .type("PASSWORD_RESET")
                    .build();

            OtpResponse response = otpService.sendOtp(request);
            
            return response;

        } catch (Exception e) {
            log.error("Error sending password reset OTP: {}", e.getMessage(), e);
            return OtpResponse.builder()
                    .success(true)
                    .message("If this email is registered, you will receive a reset code.")
                    .build();
        }
    }

    @Override
    public OtpResponse verifyPasswordResetOtp(String email, String otp) {
        log.info("=== VERIFY PASSWORD RESET OTP ===");
        log.info("Email: {}", email);

        try {
            String normalizedEmail = email.toLowerCase().trim();
            String cleanOtp = otp.trim().replaceAll("\\s+", "");

            User user = userRepository.findByEmail(normalizedEmail)
                    .orElseThrow(() -> new AuthenticationException("User not found"));

            VerifyOtpRequest otpRequest = VerifyOtpRequest.builder()
                    .email(normalizedEmail)
                    .otp(cleanOtp)
                    .type("PASSWORD_RESET")
                    .build();

            OtpResponse response = otpService.verifyOtpWithoutConsuming(otpRequest);

            return response;

        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error verifying password reset OTP: {}", e.getMessage(), e);
            return OtpResponse.builder()
                    .success(false)
                    .message("Failed to verify OTP.")
                    .remainingAttempts(0)
                    .build();
        }
    }

    @Override
    public OtpResponse resetPassword(ResetPasswordRequest request) {
        log.info("=== RESET PASSWORD ===");
        log.info("Email: {}", request.getEmail());

        try {
            String normalizedEmail = request.getEmail().toLowerCase().trim();
            String cleanOtp = request.getOtp().trim().replaceAll("\\s+", "");

            User user = userRepository.findByEmail(normalizedEmail)
                    .orElseThrow(() -> new AuthenticationException("User not found"));

            VerifyOtpRequest otpRequest = VerifyOtpRequest.builder()
                    .email(normalizedEmail)
                    .otp(cleanOtp)
                    .type("PASSWORD_RESET")
                    .build();

            // Verify AND consume OTP
            OtpResponse otpResponse = otpService.verifyOtp(otpRequest);

            if (!otpResponse.getSuccess()) {
                throw new AuthenticationException("OTP verification failed: " + otpResponse.getMessage());
            }

            // Update password
            user.setPassword(passwordEncoder.encode(request.getNewPassword()));
            userRepository.save(user);

            // Send confirmation email
            try {
                emailService.sendPasswordResetConfirmationEmail(user.getEmail());
            } catch (Exception e) {
                log.error("Failed to send confirmation email: {}", e.getMessage());
            }

            log.info("✓ Password reset successful for user: {}", user.getEmail());

            return OtpResponse.builder()
                    .success(true)
                    .message("Password reset successfully")
                    .build();

        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error during password reset: {}", e.getMessage(), e);
            throw new AuthenticationException("Password reset failed: " + e.getMessage());
        }
    }

    @Override
    public AuthResponse signup(SignupRequest signupRequest) {
        // Regular signup without OTP (legacy)
        throw new AuthenticationException("Please use OTP-based signup");
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
            String jwt = token.startsWith("Bearer ") ? token.substring(7) : token;

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
            throw new AuthenticationException("Token refresh failed");
        }
    }

    @Override
    public void signout(String token) {
        try {
            if (token != null && !token.trim().isEmpty()) {
                String jwt = token.startsWith("Bearer ") ? token.substring(7) : token;
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
    public Optional<UserDto> getUserByEmail(String email) {
        return userRepository.findByEmail(email.toLowerCase().trim())
                .map(this::convertToUserDto);
    }

    @Override
    public UserDto updateUserProfile(String email, String name, String avatarUrl) {
        User user = userRepository.findByEmail(email.toLowerCase().trim())
                .orElseThrow(() -> new AuthenticationException("User not found"));

        if (name != null && !name.trim().isEmpty()) {
            user.setName(name.trim());
        }
        if (avatarUrl != null) {
            user.setAvatarUrl(avatarUrl);
        }

        User savedUser = userRepository.save(user);
        return convertToUserDto(savedUser);
    }

    @Override
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
