package com.moveapp.movebackend.service;

import com.moveapp.movebackend.model.dto.OTPdto.*;
import com.moveapp.movebackend.model.entities.OTP;
import com.moveapp.movebackend.model.enums.OTPType;
import com.moveapp.movebackend.repository.OTPRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.ExecutionException;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class OTPService {

    private final OTPRepository otpRepository;
    private final EmailService emailService;
    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${move.otp.expiration-minutes:5}")
    private Integer otpExpirationMinutes;

    @Value("${move.otp.length:6}")
    private Integer otpLength;

    @Value("${move.otp.max-attempts:3}")
    private Integer maxAttempts;

    private static final Integer MAX_OTPS_PER_PERIOD = 5;
    private static final Integer RATE_LIMIT_MINUTES = 15;

    // ===== SEND OTP =====
    public OtpResponse sendOtp(SendOtpRequest request) {
        try {
            String email = validateAndNormalizeEmail(request.getEmail());
            OTPType otpType = parseOtpType(request.getType());

            log.info("=== SEND OTP ===");
            log.info("Email: {}, Type: {}", email, otpType);

            if (isRateLimited(email, otpType)) {
                log.warn("Rate limit exceeded for: {}", email);
                return OtpResponse.builder()
                        .success(false)
                        .message("Too many OTP requests. Please try again later.")
                        .nextAllowedTime(getNextAllowedTime(email, otpType))
                        .build();
            }

            invalidateActiveOtps(email, otpType);
            String otpCode = generateOtpCode();

            log.info("Generated OTP: '{}' (length: {}) for {}", otpCode, otpCode.length(), email);

            OTP otp = OTP.builder()
                    .email(email)
                    .otpCode(otpCode)
                    .type(otpType)
                    .expiryTime(LocalDateTime.now().plusMinutes(otpExpirationMinutes))
                    .used(false)
                    .attempts(0)
                    .maxAttempts(maxAttempts)
                    .build();

            otp = otpRepository.save(otp);
            log.info("Saved to DB - ID: {}, Code: '{}', Expiry: {}", 
                     otp.getId(), otp.getOtpCode(), otp.getExpiryTime());

            try {
                CompletableFuture<Boolean> emailFuture = emailService.sendOtpEmailAsync(email, otpCode, otpType);
                Boolean emailSent = emailFuture.get(15, TimeUnit.SECONDS);
                
                if (!emailSent) {
                    log.error("Email sending failed");
                    otp.setUsed(true);
                    otpRepository.save(otp);
                    return OtpResponse.builder()
                            .success(false)
                            .message("Failed to send OTP email. Please try again.")
                            .build();
                }
                
                log.info("Email sent successfully");
            } catch (TimeoutException e) {
                log.error("Email timeout");
                return OtpResponse.builder()
                        .success(false)
                        .message("Email sending timeout. Please try again.")
                        .build();
            } catch (InterruptedException | ExecutionException e) {
                log.error("Email sending error: {}", e.getMessage());
                otp.setUsed(true);
                otpRepository.save(otp);
                return OtpResponse.builder()
                        .success(false)
                        .message("Failed to send OTP email.")
                        .build();
            }

            return OtpResponse.builder()
                    .success(true)
                    .message("OTP sent successfully to your email")
                    .expiresInMinutes((long) otpExpirationMinutes)
                    .email(email)
                    .type(otpType.name())
                    .build();

        } catch (Exception e) {
            log.error("Error in sendOtp: {}", e.getMessage(), e);
            return OtpResponse.builder()
                    .success(false)
                    .message("Failed to send OTP. Please try again.")
                    .build();
        }
    }

    // ===== VERIFY OTP (WITHOUT CONSUMING) =====
    public OtpResponse verifyOtpWithoutConsuming(VerifyOtpRequest request) {
        log.info("=== VERIFY OTP (NOT CONSUMING) ===");
        
        try {
            String normalizedEmail = validateAndNormalizeEmail(request.getEmail());
            String cleanOtp = cleanOtpInput(request.getOtp());
            OTPType otpType = parseOtpType(request.getType());

            log.info("Email: '{}', Input OTP: '{}' (len: {}), Type: {}", 
                     normalizedEmail, cleanOtp, cleanOtp.length(), otpType);

            Optional<OTP> otpOpt = otpRepository.findByEmailAndTypeAndUsedFalse(
                    normalizedEmail, otpType);

            if (otpOpt.isEmpty()) {
                log.error("No OTP found in DB for {} / {}", normalizedEmail, otpType);
                return OtpResponse.builder()
                        .success(false)
                        .message("Invalid or expired OTP. Please request a new one.")
                        .remainingAttempts(0)
                        .build();
            }

            OTP otp = otpOpt.get();
            String storedOtp = cleanOtpInput(otp.getOtpCode());
            
            log.info("Found in DB - ID: {}, Stored OTP: '{}' (len: {})", 
                     otp.getId(), storedOtp, storedOtp.length());
            log.info("Expiry: {}, Current: {}, Expired: {}", 
                     otp.getExpiryTime(), LocalDateTime.now(), 
                     otp.getExpiryTime().isBefore(LocalDateTime.now()));

            if (otp.getExpiryTime().isBefore(LocalDateTime.now())) {
                log.warn("OTP expired");
                otp.setUsed(true);
                otpRepository.save(otp);
                return OtpResponse.builder()
                        .success(false)
                        .message("OTP has expired. Please request a new one.")
                        .remainingAttempts(0)
                        .build();
            }

            boolean matches = storedOtp.equals(cleanOtp);
            log.info("Comparison: '{}' == '{}' ? {}", storedOtp, cleanOtp, matches);

            if (!matches) {
                int currentAttempts = otp.getAttempts() != null ? otp.getAttempts() : 0;
                int newAttempts = currentAttempts + 1;
                int remainingAttempts = Math.max(0, maxAttempts - newAttempts);

                otp.setAttempts(newAttempts);
                log.warn("INVALID OTP - Attempt {}/{}", newAttempts, maxAttempts);

                if (newAttempts >= maxAttempts) {
                    otp.setUsed(true);
                    otpRepository.save(otp);
                    return OtpResponse.builder()
                            .success(false)
                            .message("Maximum attempts reached. Please request a new OTP.")
                            .remainingAttempts(0)
                            .build();
                }

                otpRepository.save(otp);
                return OtpResponse.builder()
                        .success(false)
                        .message("Invalid OTP. Please try again.")
                        .remainingAttempts(remainingAttempts)
                        .build();
            }

            log.info("SUCCESS - OTP verified (not consumed)");

            return OtpResponse.builder()
                    .success(true)
                    .message("OTP verified successfully")
                    .remainingAttempts(maxAttempts - (otp.getAttempts() != null ? otp.getAttempts() : 0))
                    .build();

        } catch (Exception e) {
            log.error("Error verifying OTP: {}", e.getMessage(), e);
            return OtpResponse.builder()
                    .success(false)
                    .message("Failed to verify OTP. Please try again.")
                    .remainingAttempts(0)
                    .build();
        }
    }

    // ===== VERIFY OTP (AND CONSUME) =====
    public OtpResponse verifyOtp(VerifyOtpRequest request) {
        log.info("=== VERIFY AND CONSUME OTP ===");
        
        try {
            String normalizedEmail = validateAndNormalizeEmail(request.getEmail());
            String cleanOtp = cleanOtpInput(request.getOtp());
            OTPType otpType = parseOtpType(request.getType());

            log.info("Email: '{}', OTP: '{}'", normalizedEmail, cleanOtp);

            Optional<OTP> otpOpt = otpRepository.findByEmailAndTypeAndUsedFalse(
                    normalizedEmail, otpType);

            if (otpOpt.isEmpty()) {
                log.error("No OTP found");
                return OtpResponse.builder()
                        .success(false)
                        .message("Invalid or expired OTP")
                        .remainingAttempts(0)
                        .build();
            }

            OTP otp = otpOpt.get();
            String storedOtp = cleanOtpInput(otp.getOtpCode());

            if (otp.getExpiryTime().isBefore(LocalDateTime.now())) {
                log.warn("OTP expired");
                otp.setUsed(true);
                otpRepository.save(otp);
                return OtpResponse.builder()
                        .success(false)
                        .message("OTP has expired. Please request a new one.")
                        .remainingAttempts(0)
                        .build();
            }

            if (!storedOtp.equals(cleanOtp)) {
                int currentAttempts = otp.getAttempts() != null ? otp.getAttempts() : 0;
                int newAttempts = currentAttempts + 1;
                int remainingAttempts = Math.max(0, maxAttempts - newAttempts);

                otp.setAttempts(newAttempts);
                log.warn("Invalid OTP - Attempt {}/{}", newAttempts, maxAttempts);

                if (newAttempts >= maxAttempts) {
                    otp.setUsed(true);
                    otpRepository.save(otp);
                    return OtpResponse.builder()
                            .success(false)
                            .message("Maximum attempts reached. Please request a new OTP.")
                            .remainingAttempts(0)
                            .build();
                }

                otpRepository.save(otp);
                return OtpResponse.builder()
                        .success(false)
                        .message("Invalid OTP. Please try again.")
                        .remainingAttempts(remainingAttempts)
                        .build();
            }

            otp.setUsed(true);
            otpRepository.save(otp);

            log.info("SUCCESS - OTP verified and consumed");

            return OtpResponse.builder()
                    .success(true)
                    .message("OTP verified successfully")
                    .remainingAttempts(0)
                    .build();

        } catch (Exception e) {
            log.error("Error: {}", e.getMessage(), e);
            return OtpResponse.builder()
                    .success(false)
                    .message("Failed to verify OTP. Please try again.")
                    .remainingAttempts(0)
                    .build();
        }
    }

    // ===== HELPER METHODS =====

    private String cleanOtpInput(String otp) {
        if (otp == null) return "";
        // Remove ALL whitespace and non-digit characters
        return otp.replaceAll("\\s+", "")
                  .replaceAll("[^0-9]", "")
                  .trim();
    }

    private void invalidateActiveOtps(String email, OTPType otpType) {
        try {
            var activeOtps = otpRepository.findByEmailAndType(email, otpType);
            int count = 0;
            for (OTP otp : activeOtps) {
                if (!otp.isUsed() && otp.getExpiryTime().isAfter(LocalDateTime.now())) {
                    otp.setUsed(true);
                    otpRepository.save(otp);
                    count++;
                }
            }
            if (count > 0) {
                log.info("Invalidated {} old OTPs", count);
            }
        } catch (Exception e) {
            log.error("Error invalidating OTPs: {}", e.getMessage());
        }
    }

    private String generateOtpCode() {
        StringBuilder otp = new StringBuilder();
        for (int i = 0; i < otpLength; i++) {
            otp.append(secureRandom.nextInt(10));
        }
        return otp.toString();
    }

    private boolean isRateLimited(String email, OTPType otpType) {
        try {
            LocalDateTime threshold = LocalDateTime.now().minusMinutes(RATE_LIMIT_MINUTES);
            Long count = otpRepository.countRecentOtpsByEmailAndType(email, otpType, threshold);
            return count >= MAX_OTPS_PER_PERIOD;
        } catch (Exception e) {
            return false;
        }
    }

    private Long getNextAllowedTime(String email, OTPType otpType) {
        try {
            LocalDateTime threshold = LocalDateTime.now().minusMinutes(RATE_LIMIT_MINUTES);
            LocalDateTime oldest = otpRepository.findOldestRecentOtpTime(email, otpType, threshold);
            if (oldest != null) {
                return oldest.plusMinutes(RATE_LIMIT_MINUTES)
                        .toEpochSecond(java.time.ZoneOffset.UTC) * 1000;
            }
        } catch (Exception e) {
            log.error("Error calculating next allowed time: {}", e.getMessage());
        }
        return null;
    }

    private String validateAndNormalizeEmail(String email) {
        if (!StringUtils.hasText(email)) {
            throw new IllegalArgumentException("Email cannot be null or empty");
        }
        String normalized = email.toLowerCase().trim();
        if (!normalized.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")) {
            throw new IllegalArgumentException("Invalid email format");
        }
        if (normalized.length() > 255) {
            throw new IllegalArgumentException("Email address too long");
        }
        return normalized;
    }

    private OTPType parseOtpType(String type) {
        if (!StringUtils.hasText(type)) {
            throw new IllegalArgumentException("OTP type cannot be null");
        }
        try {
            return OTPType.valueOf(type.toUpperCase().trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid OTP type: " + type);
        }
    }

    @Scheduled(fixedRate = 600000)
    public void cleanupExpiredOtps() {
        try {
            LocalDateTime now = LocalDateTime.now();
            LocalDateTime cutoff = now.minusHours(1);
            int deleted = otpRepository.deleteExpiredAndUsedOtps(now, cutoff);
            if (deleted > 0) {
                log.debug("Cleaned up {} expired OTPs", deleted);
            }
        } catch (Exception e) {
            log.error("Cleanup failed: {}", e.getMessage());
        }
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class OtpStatusResponse {
        private String email;
        private boolean hasActiveOtp;
        private int attemptsRemaining;
        private Long nextAllowedTime;
    }
}
