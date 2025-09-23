package com.moveapp.movebackend.oauth;

import com.moveapp.movebackend.exception.OAuth2Exception;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
        try {
            log.info("Loading OAuth2 user for registration: {}",
                    oAuth2UserRequest.getClientRegistration().getRegistrationId());

            OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);

            log.info("OAuth2 user loaded successfully. Attributes: {}",
                    oAuth2User.getAttributes().keySet());

            return processOAuth2User(oAuth2UserRequest, oAuth2User);

        } catch (OAuth2AuthenticationException ex) {
            log.error("OAuth2 authentication failed: {}", ex.getMessage(), ex);
            throw ex;
        } catch (Exception ex) {
            log.error("Unexpected error occurred during OAuth2 authentication: {}", ex.getMessage(), ex);
            // Throwing an instance of AuthenticationException will trigger OAuth2AuthenticationFailureHandler
            throw new InternalAuthenticationServiceException("OAuth2 user loading failed: " + ex.getMessage(), ex);
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
        try {
            String registrationId = oAuth2UserRequest.getClientRegistration().getRegistrationId();
            log.info("Processing OAuth2 user for provider: {}", registrationId);

            OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(registrationId, oAuth2User.getAttributes());

            // Validate email
            if (!StringUtils.hasLength(oAuth2UserInfo.getEmail())) {
                log.error("Email not found from OAuth2 provider: {}", registrationId);
                throw new OAuth2Exception("Email not found from OAuth2 provider");
            }

            log.info("Processing OAuth2 user: {} from provider: {}",
                    oAuth2UserInfo.getEmail(), registrationId);

            // Return the original OAuth2User - the actual user creation/update happens in OAuth2Service
            // This allows us to maintain the OAuth2User context through the success handler
            return oAuth2User;

        } catch (OAuth2Exception ex) {
            log.error("OAuth2 user processing failed: {}", ex.getMessage());
            throw new OAuth2AuthenticationException(ex.getMessage());
        } catch (Exception ex) {
            log.error("Unexpected error processing OAuth2 user: {}", ex.getMessage(), ex);
            throw new OAuth2AuthenticationException("Failed to process OAuth2 user: " + ex.getMessage());
        }
    }
}

// OAuth2UserInfo interface and implementations
interface OAuth2UserInfo {
    String getId();
    String getName();
    String getEmail();
    String getImageUrl();
}

class OAuth2UserInfoFactory {
    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if (registrationId == null || attributes == null) {
            throw new OAuth2Exception("Invalid OAuth2 registration or attributes");
        }

        String provider = registrationId.toLowerCase();
        switch (provider) {
            case "google":
                return new GoogleOAuth2UserInfo(attributes);
            case "github":
                return new GithubOAuth2UserInfo(attributes);
            default:
                throw new OAuth2Exception("Login with " + registrationId + " is not supported");
        }
    }
}

class GoogleOAuth2UserInfo implements OAuth2UserInfo {
    private final Map<String, Object> attributes;

    public GoogleOAuth2UserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getId() {
        return (String) attributes.get("sub");
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getImageUrl() {
        return (String) attributes.get("picture");
    }
}

class GithubOAuth2UserInfo implements OAuth2UserInfo {
    private final Map<String, Object> attributes;

    public GithubOAuth2UserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getId() {
        Object id = attributes.get("id");
        return id != null ? String.valueOf(id) : null;
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getImageUrl() {
        return (String) attributes.get("avatar_url");
    }
}