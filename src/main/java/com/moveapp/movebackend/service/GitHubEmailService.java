package com.moveapp.movebackend.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;

@Service
@Slf4j
public class GitHubEmailService {

    private final RestTemplate restTemplate = new RestTemplate();

    @SuppressWarnings("unchecked")
    public String getPrimaryEmail(OAuth2User oAuth2User, String accessToken) {
        try {
            // First try to get email from user attributes
            String email = oAuth2User.getAttribute("email");
            if (email != null && !email.isEmpty()) {
                log.debug("Got GitHub email from user attributes: {}", email);
                return email;
            }

            // If email is null, try to fetch from GitHub emails API
            if (accessToken != null) {
                HttpHeaders headers = new HttpHeaders();
                headers.setBearerAuth(accessToken);
                HttpEntity<String> entity = new HttpEntity<>(headers);

                ResponseEntity<List> response = restTemplate.exchange(
                        "https://api.github.com/user/emails",
                        HttpMethod.GET,
                        entity,
                        List.class
                );

                if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                    List<Map<String, Object>> emails = response.getBody();

                    // Find primary email
                    for (Map<String, Object> emailObj : emails) {
                        Boolean primary = (Boolean) emailObj.get("primary");
                        Boolean verified = (Boolean) emailObj.get("verified");
                        String emailAddress = (String) emailObj.get("email");

                        if (primary != null && primary && verified != null && verified && emailAddress != null) {
                            log.debug("Found GitHub primary email via API: {}", emailAddress);
                            return emailAddress;
                        }
                    }

                    // If no primary email found, try to get any verified email
                    for (Map<String, Object> emailObj : emails) {
                        Boolean verified = (Boolean) emailObj.get("verified");
                        String emailAddress = (String) emailObj.get("email");

                        if (verified != null && verified && emailAddress != null) {
                            log.debug("Found GitHub verified email via API: {}", emailAddress);
                            return emailAddress;
                        }
                    }
                }
            }

            // Fallback: create email based on login
            String login = oAuth2User.getAttribute("login");
            if (login != null) {
                String fallbackEmail = login + "@github.local";
                log.warn("Could not get GitHub email, using fallback: {}", fallbackEmail);
                return fallbackEmail;
            }

            return null;
        } catch (Exception e) {
            log.error("Error fetching GitHub email", e);
            return null;
        }
    }
}