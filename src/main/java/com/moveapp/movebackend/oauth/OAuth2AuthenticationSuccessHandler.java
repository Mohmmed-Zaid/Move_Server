package com.moveapp.movebackend.oauth;

import com.moveapp.movebackend.model.dto.AuthenticationDto.AuthResponse;
import com.moveapp.movebackend.service.OAuth2Service;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final OAuth2Service oAuth2Service;

    @Value("${move.oauth2.authorizedRedirectUri}")
    private String redirectUri;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        String targetUrl = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            log.debug("Response has already been committed. Unable to redirect to " + targetUrl);
            return;
        }

        clearAuthenticationAttributes(request);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) {

        try {
            OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();

            // Process OAuth2 authentication
            AuthResponse authResponse = oAuth2Service.handleOAuth2Success(oauth2User, authentication);

            // Build success redirect URL with token
            String targetUrl = UriComponentsBuilder.fromUriString(redirectUri)
                    .queryParam("token", authResponse.getAccessToken())
                    .queryParam("success", "true")
                    .build().toUriString();

            log.info("OAuth2 authentication successful. Redirecting to: {}", redirectUri);
            return targetUrl;

        } catch (Exception e) {
            log.error("OAuth2 authentication processing failed", e);

            // Build error redirect URL
            String errorMessage = URLEncoder.encode(e.getMessage(), StandardCharsets.UTF_8);
            String targetUrl = UriComponentsBuilder.fromUriString(redirectUri)
                    .queryParam("error", errorMessage)
                    .queryParam("success", "false")
                    .build().toUriString();

            return targetUrl;
        }
    }
}