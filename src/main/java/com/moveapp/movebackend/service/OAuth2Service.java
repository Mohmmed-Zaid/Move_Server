package com.moveapp.movebackend.service;

import com.moveapp.movebackend.exception.AuthenticationException;
import com.moveapp.movebackend.model.dto.AuthenticationDto.AuthResponse;
import com.moveapp.movebackend.model.dto.AuthenticationDto.OAuth2LinkRequest;
import com.moveapp.movebackend.model.dto.AuthenticationDto.UserDto;
import com.moveapp.movebackend.model.entities.User;
import com.moveapp.movebackend.model.enums.AuthProvider;
import com.moveapp.movebackend.repository.UserRepository;
import com.moveapp.movebackend.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class OAuth2Service {

    private final UserRepository userRepository;
    private final JwtTokenProvider tokenProvider;

    @Autowired(required = false)
    private EmailService emailService;

    /**
     * Handle OAuth2 authentication success
     */
    @Transactional
    public AuthResponse handleOAuth2Success(OAuth2User oauth2User, Authentication authentication) {
        log.info("Handling OAuth2 authentication success");

        try {
            if (oauth2User == null || authentication == null) {
                log.error("OAuth2User or Authentication is null");
                throw new AuthenticationException("Invalid OAuth2 authentication data");
            }

            // Extract user information from OAuth2 response
            OAuth2UserInfo userInfo = extractUserInfo(oauth2User, authentication);

            if (userInfo.getEmail() == null || userInfo.getEmail().trim().isEmpty()) {
                log.error("Email not provided by OAuth provider");
                throw new AuthenticationException("Email not provided by OAuth provider");
            }

            log.info("Processing OAuth2 user: {}", userInfo.getEmail());

            // Create or update user
            User user = createOrUpdateOAuthUser(userInfo, authentication);

            // Generate JWT token
            String jwt = tokenProvider.generateTokenFromEmail(user.getEmail());

            log.info("OAuth2 authentication completed successfully for user: {}", user.getEmail());

            return buildAuthResponse(jwt, user);

        } catch (AuthenticationException e) {
            log.error("OAuth2 authentication failed: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("OAuth2 authentication failed with unexpected error", e);
            throw new AuthenticationException("OAuth2 authentication failed: " + e.getMessage());
        }
    }

    /**
     * Link OAuth account to existing user account
     */
    @Transactional
    public AuthResponse linkOAuthAccount(OAuth2LinkRequest request, Authentication oauthAuthentication) {
        log.info("Linking OAuth account for user: {}", request.getEmail());

        try {
            if (request == null || oauthAuthentication == null) {
                throw new AuthenticationException("Invalid OAuth2 link request data");
            }

            // Find existing user
            User existingUser = userRepository.findByEmail(request.getEmail().toLowerCase().trim())
                    .orElseThrow(() -> new AuthenticationException("User not found"));

            // Extract OAuth user info
            OAuth2UserInfo oauthUserInfo = extractUserInfo((OAuth2User) oauthAuthentication.getPrincipal(),
                    oauthAuthentication);

            // Verify emails match
            if (!request.getEmail().equalsIgnoreCase(oauthUserInfo.getEmail())) {
                throw new AuthenticationException("OAuth email does not match account email");
            }

            // Check if OAuth account is already linked to another user
            AuthProvider oauthProvider = getProviderFromAuthentication(oauthAuthentication);
            if (oauthProvider != null && oauthUserInfo.getProviderId() != null) {
                Optional<User> existingOAuthUser = userRepository.findByProviderIdAndAuthProvider(
                        oauthUserInfo.getProviderId(), oauthProvider.name());

                if (existingOAuthUser.isPresent() && !existingOAuthUser.get().getId().equals(existingUser.getId())) {
                    throw new AuthenticationException("This OAuth account is already linked to another user");
                }
            }

            // Update user with OAuth information
            updateUserWithOAuthInfo(existingUser, oauthUserInfo, oauthProvider);
            User savedUser = userRepository.save(existingUser);

            // Generate JWT token
            String jwt = tokenProvider.generateTokenFromEmail(savedUser.getEmail());

            log.info("OAuth account linked successfully for user: {}", savedUser.getEmail());

            return buildAuthResponse(jwt, savedUser);

        } catch (Exception e) {
            log.error("Failed to link OAuth account for user: {}", request.getEmail(), e);
            throw new AuthenticationException("Failed to link OAuth account: " + e.getMessage());
        }
    }

    /**
     * Create or update OAuth user
     */
    @Transactional
    protected User createOrUpdateOAuthUser(OAuth2UserInfo userInfo, Authentication authentication) {
        log.info("Creating or updating OAuth user for email: {}", userInfo.getEmail());

        String email = userInfo.getEmail().toLowerCase().trim();
        Optional<User> existingUser = userRepository.findByEmail(email);

        if (existingUser.isPresent()) {
            return updateExistingUser(existingUser.get(), userInfo, authentication);
        } else {
            return createNewOAuthUser(userInfo, authentication);
        }
    }

    /**
     * Update existing user with OAuth information
     */
    private User updateExistingUser(User user, OAuth2UserInfo userInfo, Authentication authentication) {
        AuthProvider oauthProvider = getProviderFromAuthentication(authentication);
        boolean updated = false;

        // Update name if provided and different
        if (userInfo.getName() != null && !userInfo.getName().trim().isEmpty()
                && !userInfo.getName().trim().equals(user.getName())) {
            user.setName(userInfo.getName().trim());
            updated = true;
        }

        // Update avatar URL if provided and different
        if (userInfo.getAvatarUrl() != null && !userInfo.getAvatarUrl().equals(user.getAvatarUrl())) {
            user.setAvatarUrl(userInfo.getAvatarUrl());
            updated = true;
        }

        // Mark email as verified for OAuth users - FIX: Check method name
        if (user.getEmailVerified() != null && !user.getEmailVerified()) {
            user.setEmailVerified(true);
            updated = true;
        } else if (user.getEmailVerified() == null) {
            user.setEmailVerified(true);
            updated = true;
        }

        // Update auth provider if it was previously LOCAL or if provider ID is missing
        if (user.getAuthProvider() == AuthProvider.LOCAL || user.getProviderId() == null) {
            if (oauthProvider != null) {
                user.setAuthProvider(oauthProvider);
                user.setProviderId(userInfo.getProviderId());
                updated = true;
            }
        }

        if (updated) {
            User savedUser = userRepository.save(user);
            log.info("Updated existing OAuth user: {}", user.getEmail());
            return savedUser;
        }

        return user;
    }

    /**
     * Create new OAuth user
     */
    private User createNewOAuthUser(OAuth2UserInfo userInfo, Authentication authentication) {
        AuthProvider authProvider = getProviderFromAuthentication(authentication);
        if (authProvider == null) {
            authProvider = AuthProvider.LOCAL; // Fallback
        }

        User newUser = User.builder()
                .name(userInfo.getName() != null ? userInfo.getName().trim() : "User")
                .email(userInfo.getEmail().toLowerCase().trim())
                .password(null) // OAuth users don't have passwords
                .authProvider(authProvider)
                .providerId(userInfo.getProviderId())
                .emailVerified(true) // OAuth emails are considered verified
                .avatarUrl(userInfo.getAvatarUrl())
                .build();

        User savedUser = userRepository.save(newUser);
        log.info("Created new OAuth user: {}", savedUser.getEmail());

        // Send welcome email asynchronously
        sendWelcomeEmailAsync(savedUser);

        return savedUser;
    }

    /**
     * Extract user information from OAuth2 response
     */
    private OAuth2UserInfo extractUserInfo(OAuth2User oauth2User, Authentication authentication) {
        Map<String, Object> attributes = oauth2User.getAttributes();
        AuthProvider provider = getProviderFromAuthentication(authentication);

        String email = (String) attributes.get("email");
        String name = (String) attributes.get("name");
        String avatarUrl = null;
        String providerId = null;

        if (provider == AuthProvider.GOOGLE) {
            avatarUrl = (String) attributes.get("picture");
            providerId = (String) attributes.get("sub");
        } else if (provider == AuthProvider.GITHUB) {
            avatarUrl = (String) attributes.get("avatar_url");
            Object id = attributes.get("id");
            providerId = id != null ? String.valueOf(id) : null;

            // GitHub doesn't always provide email in main attributes
            if (email == null) {
                email = (String) attributes.get("login"); // Use login as fallback
                if (email != null && !email.contains("@")) {
                    email = email + "@github.local"; // Create a pseudo email
                }
            }
        }

        return OAuth2UserInfo.builder()
                .email(email)
                .name(name)
                .avatarUrl(avatarUrl)
                .providerId(providerId)
                .provider(provider)
                .build();
    }

    /**
     * Extract provider information from OAuth2 authentication
     */
    private AuthProvider getProviderFromAuthentication(Authentication authentication) {
        if (authentication instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
            String registrationId = oauthToken.getAuthorizedClientRegistrationId();

            return switch (registrationId.toLowerCase()) {
                case "google" -> AuthProvider.GOOGLE;
                case "github" -> AuthProvider.GITHUB;
                default -> null;
            };
        }

        // Fallback: try to determine from attributes
        if (authentication != null && authentication.getPrincipal() instanceof OAuth2User) {
            OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
            Map<String, Object> attributes = oauth2User.getAttributes();

            // Check for Google-specific attributes
            if (attributes.containsKey("sub") && attributes.containsKey("picture")) {
                return AuthProvider.GOOGLE;
            }
            // Check for GitHub-specific attributes
            if (attributes.containsKey("login") && attributes.containsKey("avatar_url")) {
                return AuthProvider.GITHUB;
            }
        }

        return null;
    }

    /**
     * Update user with OAuth information
     */
    private void updateUserWithOAuthInfo(User user, OAuth2UserInfo userInfo, AuthProvider provider) {
        if (userInfo.getName() != null && !userInfo.getName().trim().isEmpty()) {
            user.setName(userInfo.getName().trim());
        }

        if (userInfo.getAvatarUrl() != null) {
            user.setAvatarUrl(userInfo.getAvatarUrl());
        }

        if (provider != null) {
            user.setAuthProvider(provider);
            user.setProviderId(userInfo.getProviderId());
        }

        user.setEmailVerified(true); // OAuth emails are verified
    }

    /**
     * Build AuthResponse with user information
     */
    private AuthResponse buildAuthResponse(String jwt, User user) {
        return AuthResponse.builder()
                .accessToken(jwt)
                .tokenType("Bearer")
                .expiresIn(86400L) // 24 hours
                .user(convertToUserDto(user))
                .build();
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

    /**
     * Send welcome email asynchronously to avoid blocking OAuth flow
     */
    private void sendWelcomeEmailAsync(User user) {
        try {
            if (emailService != null) {
                emailService.sendWelcomeEmail(user.getEmail(), user.getName());
            }
        } catch (Exception e) {
            log.error("Failed to send welcome email to OAuth user: {}", user.getEmail(), e);
            // Don't fail the OAuth process if email sending fails
        }
    }

    /**
     * Inner class to hold OAuth2 user information
     */
    @lombok.Builder
    @lombok.Data
    private static class OAuth2UserInfo {
        private String email;
        private String name;
        private String avatarUrl;
        private String providerId;
        private AuthProvider provider;
    }
}