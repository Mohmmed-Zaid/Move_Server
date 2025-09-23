package com.moveapp.movebackend.model.dto.AuthenticationDto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthRequest {

    @Email(message = "Email should be valid")
    @NotBlank
    private String email;

    @NotBlank
    private String password;
}