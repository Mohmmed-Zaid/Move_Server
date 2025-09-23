package com.moveapp.movebackend.model.dto.AuthenticationDto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OAuth2UserRequest {
    private String email;
    private String name;
    private String avatarUrl;
    private String provider;
    private String providerId;
}
