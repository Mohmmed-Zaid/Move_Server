package com.moveapp.movebackend.oauth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Slf4j
@Component
public class OAuth2AuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Value("${move.oauth2.authorizedRedirectUri}")
    private String redirectUri;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {

        log.error("OAuth2 authentication failed", exception);

        String errorMessage = exception.getLocalizedMessage();
        if (errorMessage == null || errorMessage.trim().isEmpty()) {
            errorMessage = "OAuth2 authentication failed";
        }

        // Encode the error message to safely include in URL
        String encodedError = URLEncoder.encode(errorMessage, StandardCharsets.UTF_8);

        String targetUrl = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("error", encodedError)
                .queryParam("success", "false")
                .build().toUriString();

        log.info("Redirecting to failure URL: {}", redirectUri);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}