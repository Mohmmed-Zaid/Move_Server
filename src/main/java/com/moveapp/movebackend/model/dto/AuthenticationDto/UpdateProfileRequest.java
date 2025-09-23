package com.moveapp.movebackend.model.dto.AuthenticationDto;

import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdateProfileRequest {

    @Size(min = 2, max = 50, message = "Name should be between 2 to 50 characters")
    private String name;

    private String avatarUrl;
}