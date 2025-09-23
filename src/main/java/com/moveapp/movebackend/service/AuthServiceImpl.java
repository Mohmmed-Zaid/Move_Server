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
import org.springframework.security.oauth2.core.user.OAuth2User;
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
     * Send OTP for signup verification
     */
    @Override
    public OtpResponse sendSignupOtp(String email) {
        log.info("Sending signup OTP to email: {}", email);

        try {
            // Normalize email
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

            OtpResponse response = otpService.sendOtp(request);

            if (response.getSuccess()) {
                log.info("Signup OTP sent successfully to: {}", normalizedEmail);
            } else {
                log.warn("Failed to send signup OTP to: {} - {}", normalizedEmail, response.getMessage());
            }

            return response;

        } catch (Exception e) {
            log.error("Error sending signup OTP to: {}", email, e);
            return OtpResponse.builder()
                    .success(false)
                    .message("Failed to send OTP. Please try again.")
                    .build();
        }
    }

    /**
     * Verify signup OTP
     */
    @Override
    public OtpResponse verifySignupOtp(String email, String otp) {
        log.info("Verifying signup OTP for email: {}", email);

        try {
            // Normalize email
            String normalizedEmail = email.toLowerCase().trim();

            // Check if user already exists
            if (userRepository.existsByEmail(normalizedEmail)) {
                log.warn("Signup OTP verification for existing email: {}", normalizedEmail);
                return OtpResponse.builder()
                        .success(false)
                        .message("Email address already registered. Please login instead.")
                        .build();
            }

            // Create verify OTP request - but don't mark as used yet
            VerifyOtpRequest otpRequest = VerifyOtpRequest.builder()
                    .email(normalizedEmail)
                    .otp(otp.trim())
                    .type("SIGNUP_VERIFICATION")
                    .build();

            // Use verification method that doesn't consume the OTP yet
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
     * Register a new user with OTP verification
     */
    @Override
    public AuthResponse signupWithOtp(SignupWithOtpRequest request) {
        log.info("Processing signup with OTP for email: {}", request.getEmail());

        try {
            // Normalize email
            String normalizedEmail = request.getEmail().toLowerCase().trim();

            // Check if user already exists
            if (userRepository.existsByEmail(normalizedEmail)) {
                log.warn("Signup attempt with existing email: {}", normalizedEmail);
                throw new AuthenticationException("Email address already in use.");
            }

            // Verify and consume the OTP
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

            // Create new user
            User user = User.builder()
                    .name(request.getName().trim())
                    .email(normalizedEmail)
                    .password(passwordEncoder.encode(request.getPassword()))
                    .authProvider(AuthProvider.LOCAL)
                    .emailVerified(true) // Email is verified through OTP
                    .build();

            log.debug("Saving new user with email: {}", user.getEmail());
            User savedUser = userRepository.save(user);

            // Send welcome email (optional, don't fail signup if this fails)
            try {
                emailService.sendWelcomeEmail(savedUser.getEmail(), savedUser.getName());
                log.info("Welcome email sent to: {}", savedUser.getEmail());
            } catch (Exception e) {
                log.error("Failed to send welcome email to: {}", savedUser.getEmail(), e);
                // Don't fail the signup process if email sending fails
            }

            // Generate JWT token
            String jwt = tokenProvider.generateTokenFromEmail(savedUser.getEmail());
            log.info("Signup completed successfully for user: {}", savedUser.getEmail());

            return AuthResponse.builder()
                    .accessToken(jwt)
                    .tokenType("Bearer")
                    .expiresIn(86400L) // 24 hours
                    .user(convertToUserDto(savedUser))
                    .build();

        } catch (AuthenticationException e) {
            log.error("Authentication error during signup with OTP: {}", e.getMessage());
            throw e; // Re-throw authentication exceptions
        } catch (Exception e) {
            log.error("Unexpected error during signup with OTP for: {}", request.getEmail(), e);
            throw new AuthenticationException("Signup failed due to an unexpected error. Please try again.");
        }
    }

    /**
     * Regular signup (for backward compatibility)
     */
    @Override
    public AuthResponse signup(SignupRequest signupRequest) {
        log.info("Processing regular signup for email: {}", signupRequest.getEmail());

        try {
            // Normalize email
            String normalizedEmail = signupRequest.getEmail().toLowerCase().trim();

            // Check if user already exists
            if (userRepository.existsByEmail(normalizedEmail)) {
                log.warn("Signup attempt with existing email: {}", normalizedEmail);
                throw new AuthenticationException("Email address already in use.");
            }

            // Create new user
            User user = User.builder()
                    .name(signupRequest.getName().trim())
                    .email(normalizedEmail)
                    .password(passwordEncoder.encode(signupRequest.getPassword()))
                    .authProvider(AuthProvider.LOCAL)
                    .emailVerified(false) // Not verified in regular signup
                    .build();

            log.debug("Saving new user with email: {}", user.getEmail());
            User savedUser = userRepository.save(user);

            // Generate JWT token
            String jwt = tokenProvider.generateTokenFromEmail(savedUser.getEmail());
            log.info("Generated JWT token for new user: {}", savedUser.getEmail());

            return AuthResponse.builder()
                    .accessToken(jwt)
                    .tokenType("Bearer")
                    .expiresIn(86400L) // 24 hours
                    .user(convertToUserDto(savedUser))
                    .build();

        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error during regular signup for: {}", signupRequest.getEmail(), e);
            throw new AuthenticationException("Signup failed due to an unexpected error. Please try again.");
        }
    }

    /**
     * Authenticate user with email and password
     */
    @Override
    public AuthResponse signin(AuthRequest authRequest) {
        log.info("Processing signin for email: {}", authRequest.getEmail());

        try {
            // Normalize email
            String normalizedEmail = authRequest.getEmail().toLowerCase().trim();

            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            normalizedEmail,
                            authRequest.getPassword()
                    )
            );

            // Generate JWT token
            String jwt = tokenProvider.generateToken(authentication);

            // Get user details
            User user = userRepository.findByEmail(normalizedEmail)
                    .orElseThrow(() -> new AuthenticationException("User not found"));

            log.info("Signin successful for user: {}", user.getEmail());

            return AuthResponse.builder()
                    .accessToken(jwt)
                    .tokenType("Bearer")
                    .expiresIn(86400L) // 24 hours
                    .user(convertToUserDto(user))
                    .build();

        } catch (BadCredentialsException e) {
            log.error("Invalid credentials for email: {}", authRequest.getEmail());
            throw new AuthenticationException("Invalid email or password");
        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Authentication error for email: {}", authRequest.getEmail(), e);
            throw new AuthenticationException("Authentication failed: " + e.getMessage());
        }
    }

    /**
     * Send OTP for password reset
     */
    @Override
    public OtpResponse sendPasswordResetOtp(String email) {
        log.info("Sending password reset OTP to email: {}", email);

        try {
            // Normalize email
            String normalizedEmail = email.toLowerCase().trim();

            // Check if user exists
            if (!userRepository.existsByEmail(normalizedEmail)) {
                // Don't reveal if email exists or not for security
                return OtpResponse.builder()
                        .success(true)
                        .message("If this email is registered, you will receive an OTP shortly.")
                        .build();
            }

            SendOtpRequest request = SendOtpRequest.builder()
                    .email(normalizedEmail)
                    .type("PASSWORD_RESET")
                    .build();

            return otpService.sendOtp(request);

        } catch (Exception e) {
            log.error("Error sending password reset OTP to: {}", email, e);
            return OtpResponse.builder()
                    .success(false)
                    .message("Failed to send password reset OTP. Please try again.")
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
            // Normalize email
            String normalizedEmail = email.toLowerCase().trim();

            // Check if user exists
            User user = userRepository.findByEmail(normalizedEmail)
                    .orElseThrow(() -> new AuthenticationException("User not found"));

            // Create verify OTP request - don't consume yet
            VerifyOtpRequest otpRequest = VerifyOtpRequest.builder()
                    .email(normalizedEmail)
                    .otp(otp.trim())
                    .type("PASSWORD_RESET")
                    .build();

            // Verify but don't consume the OTP
            OtpResponse otpResponse = otpService.verifyOtpWithoutConsuming(otpRequest);

            if (otpResponse.getSuccess()) {
                log.info("Password reset OTP verified successfully for user: {}", normalizedEmail);
            } else {
                log.warn("Password reset OTP verification failed for user: {}", normalizedEmail);
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
     * Reset password with OTP verification
     */
    @Override
    public OtpResponse resetPassword(ResetPasswordRequest request) {
        log.info("Processing password reset for email: {}", request.getEmail());

        try {
            // Normalize email
            String normalizedEmail = request.getEmail().toLowerCase().trim();

            // Check if user exists
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

            // Send confirmation email
            try {
                emailService.sendPasswordResetConfirmationEmail(user.getEmail());
                log.info("Password reset confirmation email sent to: {}", user.getEmail());
            } catch (Exception e) {
                log.error("Failed to send password reset confirmation email", e);
                // Don't fail the password reset if email sending fails
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

    /**
     * General OTP verification endpoint
     */
    @Override
    public OtpResponse verifyOtp(VerifyOtpRequest request) {
        log.info("Verifying OTP for email: {} and type: {}", request.getEmail(), request.getType());

        // Route to appropriate verification method based on type
        if ("SIGNUP_VERIFICATION".equals(request.getType())) {
            return verifySignupOtp(request.getEmail(), request.getOtp());
        } else if ("PASSWORD_RESET".equals(request.getType())) {
            return verifyPasswordResetOtp(request.getEmail(), request.getOtp());
        } else {
            return otpService.verifyOtp(request);
        }
    }

    /**
     * Refresh JWT token
     */
    @Override
    public AuthResponse refreshToken(String token) {
        log.info("Processing token refresh request");

        try {
            // Extract JWT from Bearer token
            String jwt = extractJwtFromToken(token);

            // Validate the current token
            if (!tokenProvider.validateToken(jwt)) {
                log.warn("Invalid refresh token provided");
                throw new AuthenticationException("Invalid refresh token");
            }

            // Extract email from token
            String email = tokenProvider.getEmailFormatToken(jwt);

            // Get user details
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new AuthenticationException("User not found"));

            // Generate new token
            String newToken = tokenProvider.generateTokenFromEmail(email);
            log.info("Token refresh successful for user: {}", email);

            return AuthResponse.builder()
                    .accessToken(newToken)
                    .tokenType("Bearer")
                    .expiresIn(86400L) // 24 hours
                    .user(convertToUserDto(user))
                    .build();

        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error during token refresh", e);
            throw new AuthenticationException("Token refresh failed: " + e.getMessage());
        }
    }

    /**
     * Sign out user (invalidate token)
     */
    @Override
    public void signout(String token) {
        log.info("Processing signout request");

        try {
            if (token != null && !token.trim().isEmpty()) {
                String jwt = extractJwtFromToken(token);

                if (tokenProvider.validateToken(jwt)) {
                    String email = tokenProvider.getEmailFormatToken(jwt);
                    log.info("Signout successful for user: {}", email);
                } else {
                    log.warn("Invalid token provided during signout");
                }
            }

            log.info("Signout completed");

        } catch (Exception e) {
            log.error("Error during signout", e);
            // Don't throw exception for signout errors - always succeed
        }
    }

    /**
     * Create or update OAuth user
     */
    @Override
    public User createOrUpdateOAuthUser(String email, String name, String avatarUrl, Authentication authentication) {
        log.info("Creating or updating OAuth user for email: {}", email);

        String normalizedEmail = email.toLowerCase().trim();
        Optional<User> existingUser = userRepository.findByEmail(normalizedEmail);

        if (existingUser.isPresent()) {
            // Update existing user
            User user = existingUser.get();
            boolean updated = false;

            if (name != null && !name.trim().isEmpty() && !name.equals(user.getName())) {
                user.setName(name.trim());
                updated = true;
            }

            if (avatarUrl != null && !avatarUrl.equals(user.getAvatarUrl())) {
                user.setAvatarUrl(avatarUrl);
                updated = true;
            }

            // Mark email as verified for OAuth users
            if (!user.getEmailVerified()) {
                user.setEmailVerified(true);
                updated = true;
            }

            // Update auth provider if it was previously LOCAL
            if (user.getAuthProvider() == AuthProvider.LOCAL) {
                AuthProvider provider = getProviderFromAuthentication(authentication);
                if (provider != null) {
                    user.setAuthProvider(provider);
                    updated = true;
                }
            }

            if (updated) {
                User savedUser = userRepository.save(user);
                log.info("Updated existing OAuth user: {}", normalizedEmail);
                return savedUser;
            }

            return user;
        } else {
            // Create new user
            AuthProvider authProvider = getProviderFromAuthentication(authentication);
            if (authProvider == null) {
                authProvider = AuthProvider.LOCAL; // Default fallback
            }

            User newUser = User.builder()
                    .name(name != null ? name.trim() : "User")
                    .email(normalizedEmail)
                    .password(null) // OAuth users don't have passwords
                    .authProvider(authProvider)
                    .emailVerified(true) // OAuth emails are considered verified
                    .avatarUrl(avatarUrl)
                    .build();

            User savedUser = userRepository.save(newUser);
            log.info("Created new OAuth user: {}", normalizedEmail);

            // Send welcome email
            try {
                emailService.sendWelcomeEmail(savedUser.getEmail(), savedUser.getName());
            } catch (Exception e) {
                log.error("Failed to send welcome email to OAuth user: {}", normalizedEmail, e);
                // Don't fail the OAuth process if email sending fails
            }

            return savedUser;
        }
    }

    /**
     * Extract provider information from OAuth2 authentication
     */
    private AuthProvider getProviderFromAuthentication(Authentication authentication) {
        if (authentication != null && authentication.getPrincipal() instanceof OAuth2User) {
            OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();

            // Try to determine provider from attributes
            if (oauth2User.getAttribute("email") != null) {
                // Check for Google-specific attributes
                if (oauth2User.getAttribute("picture") != null &&
                        oauth2User.getAttribute("given_name") != null) {
                    return AuthProvider.GOOGLE;
                }
                // Check for GitHub-specific attributes
                if (oauth2User.getAttribute("avatar_url") != null &&
                        oauth2User.getAttribute("login") != null) {
                    return AuthProvider.GITHUB;
                }
            }
        }

        return null;
    }

    /**
     * Get user by email
     */
    @Override
    @Transactional(readOnly = true)
    public Optional<UserDto> getUserByEmail(String email) {
        log.debug("Fetching user by email: {}", email);

        return userRepository.findByEmail(email.toLowerCase().trim())
                .map(this::convertToUserDto);
    }

    /**
     * Update user profile
     */
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

    /**
     * Check if email exists
     */
    @Override
    @Transactional(readOnly = true)
    public boolean emailExists(String email) {
        return userRepository.existsByEmail(email.toLowerCase().trim());
    }

    /**
     * Link OAuth account to existing local account
     */
    @Override
    public AuthResponse linkOAuthAccount(String email, Authentication oauthAuthentication) {
        log.info("Linking OAuth account for user: {}", email);

        User user = userRepository.findByEmail(email.toLowerCase().trim())
                .orElseThrow(() -> new AuthenticationException("User not found"));

        OAuth2User oauth2User = (OAuth2User) oauthAuthentication.getPrincipal();
        String oauthEmail = oauth2User.getAttribute("email");
        String name = oauth2User.getAttribute("name");
        String avatarUrl = oauth2User.getAttribute("picture");
        if (avatarUrl == null) {
            avatarUrl = oauth2User.getAttribute("avatar_url");
        }

        // Verify emails match
        if (!email.equalsIgnoreCase(oauthEmail)) {
            throw new AuthenticationException("OAuth email does not match account email");
        }

        // Update user with OAuth info
        AuthProvider provider = getProviderFromAuthentication(oauthAuthentication);
        if (provider != null) {
            user.setAuthProvider(provider);
        }

        if (name != null && !name.trim().isEmpty()) {
            user.setName(name.trim());
        }

        if (avatarUrl != null) {
            user.setAvatarUrl(avatarUrl);
        }

        user.setEmailVerified(true); // OAuth emails are verified

        User savedUser = userRepository.save(user);

        // Generate JWT token
        String jwt = tokenProvider.generateTokenFromEmail(savedUser.getEmail());
        log.info("OAuth account linked successfully for user: {}", savedUser.getEmail());

        return AuthResponse.builder()
                .accessToken(jwt)
                .tokenType("Bearer")
                .expiresIn(86400L) // 24 hours
                .user(convertToUserDto(savedUser))
                .build();
    }

    /**
     * Handle OAuth2 authentication success
     */
    @Override
    public AuthResponse handleOAuth2Success(OAuth2User oauth2User, Authentication authentication) {
        log.info("Handling OAuth2 authentication success");

        String email = oauth2User.getAttribute("email");
        String name = oauth2User.getAttribute("name");
        String avatarUrl = oauth2User.getAttribute("picture");
        if (avatarUrl == null) {
            avatarUrl = oauth2User.getAttribute("avatar_url");
        }

        if (email == null) {
            throw new AuthenticationException("Email not provided by OAuth provider");
        }

        // Create or update user
        User user = createOrUpdateOAuthUser(email, name, avatarUrl, authentication);

        // Generate JWT token
        String jwt = tokenProvider.generateTokenFromEmail(user.getEmail());
        log.info("OAuth2 authentication completed for user: {}", user.getEmail());

        return AuthResponse.builder()
                .accessToken(jwt)
                .tokenType("Bearer")
                .expiresIn(86400L) // 24 hours
                .user(convertToUserDto(user))
                .build();
    }

    /**
     * Verify email with OTP
     */
    @Override
    public OtpResponse verifyEmail(VerifyOtpRequest request) {
        log.info("Verifying email for: {}", request.getEmail());

        // Verify OTP first
        OtpResponse otpResponse = otpService.verifyOtp(request);

        if (otpResponse.getSuccess()) {
            // Mark user email as verified
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

    /**
     * Send email verification OTP
     */
    @Override
    public OtpResponse sendEmailVerificationOtp(String email) {
        log.info("Sending email verification OTP to: {}", email);

        // Check if user exists
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

    /**
     * Extract JWT token from Authorization header
     */
    private String extractJwtFromToken(String token) {
        if (token != null && token.startsWith("Bearer ")) {
            return token.substring(7);
        }
        return token;
    }

    /**
     * Convert User entity to UserDto
     */
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