package com.moveapp.movebackend.model.dto.NavigationDto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NavigationStatusResponse {
    private Boolean hasActiveNavigation;
    private NavigationResponse activeSession;
}