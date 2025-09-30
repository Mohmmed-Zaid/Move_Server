package com.moveapp.movebackend.controller;

import com.moveapp.movebackend.model.dto.ApiResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/test")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = {"http://localhost:5173", "https://move-ui-three.vercel.app"})
public class TestController {

    @GetMapping("/public")
    public ResponseEntity<ApiResponse<Map<String, Object>>> publicEndpoint() {
        Map<String, Object> data = new HashMap<>();
        data.put("message", "Public endpoint working");
        data.put("timestamp", LocalDateTime.now().toString());
        data.put("authenticated", false);

        return ResponseEntity.ok(ApiResponse.success(data, "Public test endpoint successful"));
    }

    @GetMapping("/protected")
    public ResponseEntity<ApiResponse<Map<String, Object>>> protectedEndpoint(Authentication authentication) {
        Map<String, Object> data = new HashMap<>();
        data.put("message", "Protected endpoint working");
        data.put("timestamp", LocalDateTime.now().toString());
        data.put("authenticated", true);
        data.put("user", authentication.getName());
        data.put("authorities", authentication.getAuthorities());

        return ResponseEntity.ok(ApiResponse.success(data, "Protected test endpoint successful"));
    }

    @PostMapping("/echo")
    public ResponseEntity<ApiResponse<Map<String, Object>>> echo(@RequestBody Map<String, Object> payload) {
        Map<String, Object> data = new HashMap<>();
        data.put("received", payload);
        data.put("timestamp", LocalDateTime.now().toString());
        data.put("size", payload.size());

        return ResponseEntity.ok(ApiResponse.success(data, "Echo test successful"));
    }

    @GetMapping("/error")
    public ResponseEntity<ApiResponse<Void>> errorTest() {
        return ResponseEntity.badRequest()
                .body(ApiResponse.error("This is a test error", "TEST_ERROR"));
    }

    @GetMapping("/exception")
    public ResponseEntity<ApiResponse<Void>> exceptionTest() {
        throw new RuntimeException("This is a test exception");
    }
}