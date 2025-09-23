package com.moveapp.movebackend.controller;

import com.moveapp.movebackend.model.dto.ApiResponse;
import com.moveapp.movebackend.model.dto.AuthenticationDto.AuthResponse;
import com.moveapp.movebackend.model.dto.AuthenticationDto.OAuth2LinkRequest;
import com.moveapp.movebackend.model.dto.AuthenticationDto.UserDto;
import com.moveapp.movebackend.model.entities.User;
import com.moveapp.movebackend.repository.UserRepository;
import com.moveapp.movebackend.service.OAuth2Service;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/oauth2")
@RequiredArgsConstructor
@Slf4j
public class OAuth2Controller {

    private final OAuth2Service oAuth2Service;
    private final UserRepository userRepository;
    /**
     * Link OAuth2 account to existing user account
     */
    @PostMapping("/link")
    public ResponseEntity<AuthResponse> linkOAuth2Account(
            @Valid @RequestBody OAuth2LinkRequest request,
            HttpServletRequest httpRequest) {

        log.info("OAuth2 account linking request for email: {}", request.getEmail());

        try {
            // Get OAuth2 authentication from session or security context
            Authentication oauthAuthentication = getOAuth2AuthenticationFromRequest(httpRequest);

            if (oauthAuthentication == null) {
                return ResponseEntity.badRequest()
                        .body(AuthResponse.builder()
                                .build());
            }

            AuthResponse response = oAuth2Service.linkOAuthAccount(request, oauthAuthentication);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("OAuth2 account linking failed for email: {}", request.getEmail(), e);
            return ResponseEntity.badRequest()
                    .body(AuthResponse.builder()
                            .build());
        }
    }

    /**
     * Get OAuth2 user info from current authentication
     */
    @GetMapping("/user")
    public ResponseEntity<Map<String, Object>> getCurrentOAuth2User() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication == null || !authentication.isAuthenticated()) {
                return ResponseEntity.status(401).build();
            }

            Map<String, Object> userInfo = new HashMap<>();
            userInfo.put("name", authentication.getName());
            userInfo.put("authorities", authentication.getAuthorities());
            userInfo.put("authenticated", authentication.isAuthenticated());

            return ResponseEntity.ok(userInfo);

        } catch (Exception e) {
            log.error("Failed to get current OAuth2 user", e);
            return ResponseEntity.status(500).build();
        }
    }

    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserDto>> getCurrentUser() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication == null || !authentication.isAuthenticated()
                    || "anonymousUser".equals(authentication.getName())) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(ApiResponse.<UserDto>builder()
                                .success(false)
                                .message("User not authenticated")
                                .error("UNAUTHORIZED")
                                .timestamp(System.currentTimeMillis())
                                .build());
            }

            String email = authentication.getName();
            log.info("Getting current user profile for: {}", email);

            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found"));

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

            return ResponseEntity.ok(
                    ApiResponse.<UserDto>builder()
                            .success(true)
                            .message("User profile retrieved successfully")
                            .data(userDto)
                            .timestamp(System.currentTimeMillis())
                            .build()
            );

        } catch (Exception e) {
            log.error("Failed to get current user", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.<UserDto>builder()
                            .success(false)
                            .message("Failed to retrieve user profile")
                            .error("INTERNAL_ERROR")
                            .timestamp(System.currentTimeMillis())
                            .build());
        }
    }


    /**
     * Check OAuth2 providers status
     */
    @GetMapping("/providers")
    public ResponseEntity<Map<String, Object>> getAvailableProviders() {
        Map<String, Object> providers = new HashMap<>();

        Map<String, Object> google = new HashMap<>();
        google.put("name", "Google");
        google.put("enabled", true);
        google.put("authorizationUri", "/oauth2/authorization/google");

        Map<String, Object> github = new HashMap<>();
        github.put("name", "GitHub");
        github.put("enabled", true);
        github.put("authorizationUri", "/oauth2/authorization/github");

        providers.put("google", google);
        providers.put("github", github);

        return ResponseEntity.ok(providers);
    }



    /**
     * Unlink OAuth2 account (placeholder for future implementation)
     */
    @PostMapping("/unlink")
    public ResponseEntity<Map<String, String>> unlinkOAuth2Account(
            @RequestParam String provider) {

        log.info("OAuth2 account unlinking request for provider: {}", provider);

        // This would be implemented to remove OAuth2 link from user account
        // For now, return success response
        Map<String, String> response = new HashMap<>();
        response.put("message", "OAuth2 account unlink feature coming soon");
        response.put("provider", provider);

        return ResponseEntity.ok(response);
    }

    /**
     * Extract OAuth2 authentication from request
     * This is a simplified version - in real implementation, you might store
     * OAuth2 authentication in session or handle it differently
     */
    private Authentication getOAuth2AuthenticationFromRequest(HttpServletRequest request) {
        // In a real implementation, you would retrieve OAuth2 authentication
        // from session, security context, or another secure storage mechanism

        // For now, return current authentication if it exists
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null && auth.isAuthenticated()) {
            return auth;
        }

        return null;
    }
}