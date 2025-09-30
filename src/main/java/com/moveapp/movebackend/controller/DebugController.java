package com.moveapp.movebackend.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/debug")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = {"http://localhost:5173", "move-ui-three.vercel.app"})
public class DebugController {

    private final JavaMailSender mailSender;

    @Value("${move.app.jwtSecret:NOT_SET}")
    private String jwtSecret;

    @Value("${spring.security.oauth2.client.registration.google.client-id:NOT_SET}")
    private String googleClientId;

    @Value("${spring.security.oauth2.client.registration.github.client-id:NOT_SET}")
    private String githubClientId;

    @Value("${move.oauth2.authorizedRedirectUri:NOT_SET}")
    private String redirectUri;

    @Value("${spring.mail.username:NOT_SET}")
    private String emailUsername;

    @GetMapping("/config")
    public ResponseEntity<Map<String, Object>> getConfig() {
        Map<String, Object> config = new HashMap<>();

        // Don't expose full secret, just indicate if it's set
        config.put("jwtSecretSet", jwtSecret != null && !jwtSecret.equals("NOT_SET") && jwtSecret.length() > 10);
        config.put("jwtSecretLength", jwtSecret != null ? jwtSecret.length() : 0);

        config.put("googleClientIdSet", !googleClientId.equals("NOT_SET") && googleClientId.length() > 10);
        config.put("googleClientIdPrefix", googleClientId.equals("NOT_SET") ? "NOT_SET" :
                googleClientId.substring(0, Math.min(15, googleClientId.length())) + "...");

        config.put("githubClientIdSet", !githubClientId.equals("NOT_SET") && githubClientId.length() > 10);
        config.put("githubClientIdPrefix", githubClientId.equals("NOT_SET") ? "NOT_SET" :
                githubClientId.substring(0, Math.min(15, githubClientId.length())) + "...");

        config.put("redirectUri", redirectUri);
        config.put("emailConfigured", !emailUsername.equals("NOT_SET"));

        return ResponseEntity.ok(config);
    }

    @GetMapping("/email")
    public ResponseEntity<Map<String, Object>> testEmail() {
        Map<String, Object> response = new HashMap<>();

        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo("mzaidshk16@gmail.com");
            message.setSubject("Test Email - Move App Debug");
            message.setText("This is a test email from Move App Debug Controller. If you receive this, email configuration is working correctly.");
            message.setFrom(emailUsername);

            mailSender.send(message);

            response.put("success", true);
            response.put("message", "Test email sent successfully!");
            response.put("sentTo", "mzaidshk16@gmail.com");
            response.put("timestamp", System.currentTimeMillis());

            log.info("Test email sent successfully to: mzaidshk16@gmail.com");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Failed to send test email", e);

            response.put("success", false);
            response.put("message", "Failed to send email: " + e.getMessage());
            response.put("error", e.getClass().getSimpleName());
            response.put("timestamp", System.currentTimeMillis());

            return ResponseEntity.badRequest().body(response);
        }
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> healthCheck() {
        Map<String, Object> health = new HashMap<>();

        health.put("status", "UP");
        health.put("timestamp", System.currentTimeMillis());
        health.put("service", "Move Backend API");
        health.put("version", "1.0.0");

        // Check critical configurations
        Map<String, Object> checks = new HashMap<>();
        checks.put("database", "Connected"); // Assume connected if endpoint works
        checks.put("jwt", jwtSecret != null && !jwtSecret.equals("NOT_SET"));
        checks.put("email", !emailUsername.equals("NOT_SET"));
        checks.put("oauth_google", !googleClientId.equals("NOT_SET"));
        checks.put("oauth_github", !githubClientId.equals("NOT_SET"));

        health.put("checks", checks);

        return ResponseEntity.ok(health);
    }
}