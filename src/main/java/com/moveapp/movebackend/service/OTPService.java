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
import java.util.List;
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

    // ===== MAIN OTP METHODS =====

    public OtpResponse sendOtp(SendOtpRequest request) {
        try {
            String email = validateAndNormalizeEmail(request.getEmail());
            OTPType otpType = parseOtpType(request.getType());

            log.info("Processing OTP send for email: {} and type: {}", email, otpType);

            // Check rate limiting
            if (isRateLimited(email, otpType)) {
                log.warn("Rate limit exceeded for email: {} and type: {}", email, otpType);
                return OtpResponse.builder()
                        .success(false)
                        .message("Too many OTP requests. Please try again later.")
                        .nextAllowedTime(getNextAllowedTime(email, otpType))
                        .build();
            }

            // Invalidate any existing active OTPs
            invalidateActiveOtps(email, otpType);

            // Generate new OTP
            String otpCode = generateOtpCode();

            // Create and save OTP
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
            log.info("OTP created with ID: {} for email: {}", otp.getId(), email);

            // Send OTP via email with timeout
            try {
                CompletableFuture<Boolean> emailFuture = emailService.sendOtpEmailAsync(email, otpCode, otpType);
                Boolean emailSent = emailFuture.get(15, TimeUnit.SECONDS); // 5 second timeout
                
                if (!emailSent) {
                    log.warn("Email sending failed for: {}", email);
                    otp.setUsed(true);
                    otpRepository.save(otp);

                    return OtpResponse.builder()
                            .success(false)
                            .message("Failed to send OTP email. Please try again.")
                            .build();
                } else {
                    log.info("OTP email sent successfully to: {}", email);
                }
            } catch (TimeoutException e) {
                log.error("Email sending timeout for {}: {}", email, e.getMessage());
                otp.setUsed(true);
                otpRepository.save(otp);

                return OtpResponse.builder()
                        .success(false)
                        .message("Email sending timeout. Please try again.")
                        .build();
            } catch (InterruptedException e) {
                log.error("Email sending interrupted for {}: {}", email, e.getMessage());
                Thread.currentThread().interrupt(); // Restore interrupt status
                otp.setUsed(true);
                otpRepository.save(otp);

                return OtpResponse.builder()
                        .success(false)
                        .message("Failed to send OTP email. Please try again.")
                        .build();
            } catch (ExecutionException e) {
                log.error("Failed to send OTP email to {}: {}", email, e.getMessage());
                otp.setUsed(true);
                otpRepository.save(otp);

                return OtpResponse.builder()
                        .success(false)
                        .message("Failed to send OTP email. Please try again.")
                        .build();
            }

            return OtpResponse.builder()
                    .success(true)
                    .message("OTP sent successfully to your email")
                    .expiresInMinutes((long) otpExpirationMinutes)
                    .email(email)
                    .type(otpType.name())
                    .build();

        } catch (IllegalArgumentException e) {
            log.error("Invalid argument in sendOtp: {}", e.getMessage());
            return OtpResponse.builder()
                    .success(false)
                    .message(e.getMessage())
                    .build();
        } catch (Exception e) {
            log.error("Failed to send OTP for email {}: {}", request.getEmail(), e.getMessage(), e);
            return OtpResponse.builder()
                    .success(false)
                    .message("Failed to send OTP. Please try again.")
                    .build();
        }
    }


    public OtpResponse verifyOtp(VerifyOtpRequest request) {
        log.info("Verifying and consuming OTP for email: {} and type: {}", request.getEmail(), request.getType());

        try {
            // Normalize email
            String normalizedEmail = request.getEmail().toLowerCase().trim();

            // Find OTP entry
            Optional<OTP> otpOpt = otpRepository.findByEmailAndTypeAndUsedFalse(
                    normalizedEmail,
                    OTPType.valueOf(request.getType())
            );

            if (otpOpt.isEmpty()) {
                log.warn("No valid OTP found for email: {} and type: {}", normalizedEmail, request.getType());
                return OtpResponse.builder()
                        .success(false)
                        .message("Invalid or expired OTP")
                        .remainingAttempts(0)
                        .build();
            }

            OTP otp = otpOpt.get();

            // Check if OTP is expired
            if (otp.getExpiresAt().isBefore(LocalDateTime.now())) {
                log.warn("Expired OTP for email: {} and type: {}", normalizedEmail, request.getType());
                // Mark as used to prevent reuse
                otp.setUsed(true);
                otpRepository.save(otp);

                return OtpResponse.builder()
                        .success(false)
                        .message("OTP has expired. Please request a new one.")
                        .remainingAttempts(0)
                        .build();
            }

            // Verify OTP code
            if (!otp.getOtpCode().equals(request.getOtp().trim())) {
                // Increment attempt count
                int currentAttempts = otp.getAttempts() != null ? otp.getAttempts() : 0;
                int newAttempts = currentAttempts + 1;
                int remainingAttempts = Math.max(0,MAX_OTPS_PER_PERIOD - newAttempts);

                otp.setAttempts(newAttempts);

                // If max attempts reached, mark as used
                if (newAttempts >= MAX_OTPS_PER_PERIOD) {
                    otp.setUsed(true);
                    otpRepository.save(otp);

                    log.warn("Maximum OTP attempts reached for email: {} and type: {}", normalizedEmail, request.getType());
                    return OtpResponse.builder()
                            .success(false)
                            .message("Maximum attempts reached. Please request a new OTP.")
                            .remainingAttempts(0)
                            .build();
                } else {
                    otpRepository.save(otp);

                    log.warn("Invalid OTP for email: {} and type: {}, attempts: {}", normalizedEmail, request.getType(), newAttempts);
                    return OtpResponse.builder()
                            .success(false)
                            .message("Invalid OTP. Please try again.")
                            .remainingAttempts(remainingAttempts)
                            .build();
                }
            }

            // OTP is valid - mark as used to consume it
            otp.setUsed(true);
            otpRepository.save(otp);

            log.info("OTP verified and consumed successfully for email: {} and type: {}", normalizedEmail, request.getType());

            return OtpResponse.builder()
                    .success(true)
                    .message("OTP verified successfully")
                    .remainingAttempts(0)
                    .build();

        } catch (Exception e) {
            log.error("Error verifying OTP for email: {} and type: {}", request.getEmail(), request.getType(), e);
            return OtpResponse.builder()
                    .success(false)
                    .message("Failed to verify OTP. Please try again.")
                    .remainingAttempts(0)
                    .build();
        }
    }

    public OtpResponse verifyOtpForSignup(VerifyOtpRequest request) {
        try {
            String email = validateAndNormalizeEmail(request.getEmail());
            OTPType otpType = OTPType.SIGNUP_VERIFICATION; // Force signup verification type
            String otpCode = validateOtpCode(request.getOtp());

            log.info("Processing OTP verification for signup (non-consuming) for email: {} and type: {}", email, otpType);

            Optional<OTP> otpOptional = otpRepository.findActiveOtpByEmailAndType(
                    email, otpType, LocalDateTime.now());

            if (otpOptional.isEmpty()) {
                log.warn("No active SIGNUP_VERIFICATION OTP found for email: {}", email);
                // Also check if there's any active OTP for debugging
                Optional<OTP> anyActiveOtp = otpRepository.findActiveOtpByEmail(email, LocalDateTime.now());
                if (anyActiveOtp.isPresent()) {
                    log.info("Found active OTP of type: {} for email: {}", anyActiveOtp.get().getType(), email);
                }
                return OtpResponse.builder()
                        .success(false)
                        .message("No valid signup OTP found. Please request a new one.")
                        .build();
            }

            OTP otp = otpOptional.get();
            log.info("Found signup OTP with ID: {}, code: {}, attempts: {}", otp.getId(), otp.getOtpCode(), otp.getAttempts());

            if (otp.getExpiryTime().isBefore(LocalDateTime.now())) {
                log.warn("Expired OTP verification attempt for email: {}", email);
                otp.setUsed(true);
                otpRepository.save(otp);

                return OtpResponse.builder()
                        .success(false)
                        .message("OTP has expired. Please request a new one.")
                        .build();
            }

            if (otp.isMaxAttemptsReached()) {
                log.warn("Max attempts reached for OTP verification for email: {}", email);
                return OtpResponse.builder()
                        .success(false)
                        .message("Maximum attempts reached. Please request a new OTP.")
                        .remainingAttempts(0)
                        .build();
            }

            // Verify OTP code WITHOUT consuming it
            if (!otp.getOtpCode().equals(otpCode)) {
                otp.setAttempts(otp.getAttempts() + 1);
                otpRepository.save(otp);

                int remainingAttempts = maxAttempts - otp.getAttempts();
                log.warn("Invalid OTP code for email: {}. Expected: {}, Got: {}. Remaining attempts: {}",
                        email, otp.getOtpCode(), otpCode, remainingAttempts);

                return OtpResponse.builder()
                        .success(false)
                        .message("Invalid OTP code")
                        .remainingAttempts(remainingAttempts)
                        .build();
            }

            log.info("OTP verified successfully for signup (non-consuming) for {} with type {}", email, otpType);

            return OtpResponse.builder()
                    .success(true)
                    .message("OTP verified successfully")
                    .email(email)
                    .type(otpType.name())
                    .remainingAttempts(maxAttempts - otp.getAttempts())
                    .build();

        } catch (Exception e) {
            log.error("Failed to verify OTP for signup for email {}: {}", request.getEmail(), e.getMessage(), e);
            return OtpResponse.builder()
                    .success(false)
                    .message("OTP verification failed. Please try again.")
                    .build();
        }
    }

    public OtpResponse verifyOtpForPasswordReset(VerifyOtpRequest request) {
        try {
            String email = validateAndNormalizeEmail(request.getEmail());
            OTPType otpType = OTPType.PASSWORD_RESET; // Force password reset verification type
            String otpCode = validateOtpCode(request.getOtp());

            log.info("Processing OTP verification for password reset (non-consuming) for email: {} and type: {}", email, otpType);

            Optional<OTP> otpOptional = otpRepository.findActiveOtpByEmailAndType(
                    email, otpType, LocalDateTime.now());

            if (otpOptional.isEmpty()) {
                log.warn("No active PASSWORD_RESET OTP found for email: {}", email);
                return OtpResponse.builder()
                        .success(false)
                        .message("No valid password reset OTP found. Please request a new one.")
                        .build();
            }

            OTP otp = otpOptional.get();
            log.info("Found password reset OTP with ID: {}, code: {}, attempts: {}", otp.getId(), otp.getOtpCode(), otp.getAttempts());

            if (otp.getExpiryTime().isBefore(LocalDateTime.now())) {
                log.warn("Expired OTP verification attempt for email: {}", email);
                otp.setUsed(true);
                otpRepository.save(otp);

                return OtpResponse.builder()
                        .success(false)
                        .message("OTP has expired. Please request a new one.")
                        .build();
            }

            if (otp.isMaxAttemptsReached()) {
                log.warn("Max attempts reached for OTP verification for email: {}", email);
                return OtpResponse.builder()
                        .success(false)
                        .message("Maximum attempts reached. Please request a new OTP.")
                        .remainingAttempts(0)
                        .build();
            }

            // Verify OTP code WITHOUT consuming it
            if (!otp.getOtpCode().equals(otpCode)) {
                otp.setAttempts(otp.getAttempts() + 1);
                otpRepository.save(otp);

                int remainingAttempts = maxAttempts - otp.getAttempts();
                log.warn("Invalid OTP code for password reset for email: {}. Expected: {}, Got: {}. Remaining attempts: {}",
                        email, otp.getOtpCode(), otpCode, remainingAttempts);

                return OtpResponse.builder()
                        .success(false)
                        .message("Invalid OTP code")
                        .remainingAttempts(remainingAttempts)
                        .build();
            }

            log.info("OTP verified successfully for password reset (non-consuming) for {} with type {}", email, otpType);

            return OtpResponse.builder()
                    .success(true)
                    .message("OTP verified successfully")
                    .email(email)
                    .type(otpType.name())
                    .remainingAttempts(maxAttempts - otp.getAttempts())
                    .build();

        } catch (Exception e) {
            log.error("Failed to verify OTP for password reset for email {}: {}", request.getEmail(), e.getMessage(), e);
            return OtpResponse.builder()
                    .success(false)
                    .message("OTP verification failed. Please try again.")
                    .build();
        }
    }

    public OtpResponse verifyAndConsumeOtp(VerifyOtpRequest request) {
        try {
            String email = validateAndNormalizeEmail(request.getEmail());
            OTPType otpType = parseOtpType(request.getType());
            String otpCode = validateOtpCode(request.getOtp());

            log.info("Processing OTP verification and consumption for email: {} and type: {}", email, otpType);

            Optional<OTP> otpOptional = otpRepository.findActiveOtpByEmailAndType(
                    email, otpType, LocalDateTime.now());

            if (otpOptional.isEmpty()) {
                log.warn("No active OTP found for email: {} and type: {}", email, otpType);
                return OtpResponse.builder()
                        .success(false)
                        .message("No valid OTP found. Please request a new one.")
                        .build();
            }

            OTP otp = otpOptional.get();

            if (otp.getExpiryTime().isBefore(LocalDateTime.now())) {
                log.warn("Expired OTP verification attempt for email: {}", email);
                otp.setUsed(true);
                otpRepository.save(otp);

                return OtpResponse.builder()
                        .success(false)
                        .message("OTP has expired. Please request a new one.")
                        .build();
            }

            if (otp.isUsed()) {
                log.warn("OTP already used for email: {} and type: {}", email, otpType);
                return OtpResponse.builder()
                        .success(false)
                        .message("OTP has already been used. Please request a new one.")
                        .build();
            }

            if (otp.isMaxAttemptsReached()) {
                log.warn("Max attempts reached for OTP verification for email: {}", email);
                return OtpResponse.builder()
                        .success(false)
                        .message("Maximum attempts reached. Please request a new OTP.")
                        .remainingAttempts(0)
                        .build();
            }

            if (!otp.getOtpCode().equals(otpCode)) {
                otp.setAttempts(otp.getAttempts() + 1);
                otpRepository.save(otp);

                int remainingAttempts = maxAttempts - otp.getAttempts();
                log.warn("Invalid OTP code for email: {}. Remaining attempts: {}", email, remainingAttempts);

                return OtpResponse.builder()
                        .success(false)
                        .message("Invalid OTP code")
                        .remainingAttempts(remainingAttempts)
                        .build();
            }

            // Mark OTP as used (consume it)
            otp.setUsed(true);
            otpRepository.save(otp);

            log.info("OTP verified and consumed successfully for {} with type {}", email, otpType);

            return OtpResponse.builder()
                    .success(true)
                    .message("OTP verified successfully")
                    .email(email)
                    .type(otpType.name())
                    .build();

        } catch (Exception e) {
            log.error("Failed to verify and consume OTP for email {}: {}", request.getEmail(), e.getMessage(), e);
            return OtpResponse.builder()
                    .success(false)
                    .message("OTP verification failed. Please try again.")
                    .build();
        }
    }

    // ===== STATUS AND UTILITY METHODS =====

    public boolean isOtpVerified(String email, OTPType otpType) {
        try {
            String normalizedEmail = validateAndNormalizeEmail(email);
            LocalDateTime recentTime = LocalDateTime.now().minusMinutes(10);

            return otpRepository.findByEmailAndType(normalizedEmail, otpType)
                    .stream()
                    .anyMatch(otp -> otp.isUsed() &&
                            otp.getUpdatedAt() != null &&
                            otp.getUpdatedAt().isAfter(recentTime));
        } catch (Exception e) {
            log.error("Error checking OTP verification status for email {}: {}", email, e.getMessage());
            return false;
        }
    }

    public OtpStatusResponse getOtpStatus(String email) {
        try {
            String normalizedEmail = validateAndNormalizeEmail(email);
            LocalDateTime now = LocalDateTime.now();

            Optional<OTP> activeOtp = otpRepository.findActiveOtpByEmail(normalizedEmail, now);

            boolean hasActiveOtp = activeOtp.isPresent();
            int attemptsRemaining = maxAttempts;
            if (hasActiveOtp) {
                attemptsRemaining = maxAttempts - activeOtp.get().getAttempts();
            }

            Long nextAllowedTime = null;
            if (isRateLimited(normalizedEmail, OTPType.SIGNUP_VERIFICATION) ||
                    isRateLimited(normalizedEmail, OTPType.PASSWORD_RESET)) {
                Long signupTime = getNextAllowedTime(normalizedEmail, OTPType.SIGNUP_VERIFICATION);
                Long passwordTime = getNextAllowedTime(normalizedEmail, OTPType.PASSWORD_RESET);

                if (signupTime != null && passwordTime != null) {
                    nextAllowedTime = Math.min(signupTime, passwordTime);
                } else if (signupTime != null) {
                    nextAllowedTime = signupTime;
                } else {
                    nextAllowedTime = passwordTime;
                }
            }

            return OtpStatusResponse.builder()
                    .email(normalizedEmail)
                    .hasActiveOtp(hasActiveOtp)
                    .attemptsRemaining(attemptsRemaining)
                    .nextAllowedTime(nextAllowedTime)
                    .build();

        } catch (Exception e) {
            log.error("Error getting OTP status for email {}: {}", email, e.getMessage());

            return OtpStatusResponse.builder()
                    .email(email)
                    .hasActiveOtp(false)
                    .attemptsRemaining(maxAttempts)
                    .nextAllowedTime(null)
                    .build();
        }
    }

    // ===== RATE LIMITING METHODS =====

    private boolean isRateLimited(String email, OTPType otpType) {
        try {
            LocalDateTime timeThreshold = LocalDateTime.now().minusMinutes(RATE_LIMIT_MINUTES);
            Long recentOtpCount = otpRepository.countRecentOtpsByEmailAndType(email, otpType, timeThreshold);
            boolean isLimited = recentOtpCount >= MAX_OTPS_PER_PERIOD;

            if (isLimited) {
                log.info("Rate limit check: {} OTPs sent for {} in last {} minutes",
                        recentOtpCount, email, RATE_LIMIT_MINUTES);
            }

            return isLimited;
        } catch (Exception e) {
            log.error("Error checking rate limit for email {}: {}", email, e.getMessage());
            return false;
        }
    }

    public OtpResponse verifyOtpWithoutConsuming(VerifyOtpRequest request) {
        log.info("Verifying OTP without consuming for email: {} and type: {}", request.getEmail(), request.getType());

        try {
            // Normalize email
            String normalizedEmail = request.getEmail().toLowerCase().trim();

            // Find OTP entry
            Optional<OTP> otpOpt = otpRepository.findByEmailAndTypeAndUsedFalse(
                    normalizedEmail,
                    OTPType.valueOf(request.getType())
            );

            if (otpOpt.isEmpty()) {
                log.warn("No valid OTP found for email: {} and type: {}", normalizedEmail, request.getType());
                return OtpResponse.builder()
                        .success(false)
                        .message("Invalid or expired OTP")
                        .remainingAttempts(0)
                        .build();
            }

            OTP otp = otpOpt.get();

            // Check if OTP is expired
            if (otp.getExpiresAt().isBefore(LocalDateTime.now())) {
                log.warn("Expired OTP for email: {} and type: {}", normalizedEmail, request.getType());
                // Mark as used to prevent reuse
                otp.setUsed(true);
                otpRepository.save(otp);

                return OtpResponse.builder()
                        .success(false)
                        .message("OTP has expired. Please request a new one.")
                        .remainingAttempts(0)
                        .build();
            }

            // Verify OTP code
            if (!otp.getOtpCode().equals(request.getOtp().trim())) {
                // Increment attempt count
                int currentAttempts = otp.getAttempts() != null ? otp.getAttempts() : 0;
                int newAttempts = currentAttempts + 1;
                int remainingAttempts = Math.max(0, MAX_OTPS_PER_PERIOD - newAttempts);

                otp.setAttempts(newAttempts);

                // If max attempts reached, mark as used
                if (newAttempts >= MAX_OTPS_PER_PERIOD) {
                    otp.setUsed(true);
                    otpRepository.save(otp);

                    log.warn("Maximum OTP attempts reached for email: {} and type: {}", normalizedEmail, request.getType());
                    return OtpResponse.builder()
                            .success(false)
                            .message("Maximum attempts reached. Please request a new OTP.")
                            .remainingAttempts(0)
                            .build();
                } else {
                    otpRepository.save(otp);

                    log.warn("Invalid OTP for email: {} and type: {}, attempts: {}", normalizedEmail, request.getType(), newAttempts);
                    return OtpResponse.builder()
                            .success(false)
                            .message("Invalid OTP. Please try again.")
                            .remainingAttempts(remainingAttempts)
                            .build();
                }
            }

            // OTP is valid - DO NOT mark as used, just verify
            log.info("OTP verified successfully (not consumed) for email: {} and type: {}", normalizedEmail, request.getType());

            return OtpResponse.builder()
                    .success(true)
                    .message("OTP verified successfully")
                    .remainingAttempts(Math.max(0, MAX_OTPS_PER_PERIOD - (otp.getAttempts() != null ? otp.getAttempts() : 0)))
                    .build();

        } catch (Exception e) {
            log.error("Error verifying OTP without consuming for email: {} and type: {}", request.getEmail(), request.getType(), e);
            return OtpResponse.builder()
                    .success(false)
                    .message("Failed to verify OTP. Please try again.")
                    .remainingAttempts(0)
                    .build();
        }
    }


    private Long getNextAllowedTime(String email, OTPType otpType) {
        try {
            LocalDateTime timeThreshold = LocalDateTime.now().minusMinutes(RATE_LIMIT_MINUTES);
            LocalDateTime oldestRecentOtp = otpRepository.findOldestRecentOtpTime(email, otpType, timeThreshold);

            if (oldestRecentOtp != null) {
                return oldestRecentOtp.plusMinutes(RATE_LIMIT_MINUTES)
                        .toEpochSecond(java.time.ZoneOffset.UTC) * 1000;
            }
        } catch (Exception e) {
            log.error("Error calculating next allowed time: {}", e.getMessage());
        }
        return null;
    }

    // ===== INTERNAL UTILITY METHODS =====

    private void invalidateActiveOtps(String email, OTPType otpType) {
        try {
            int invalidatedCount = 0;
            var activeOtps = otpRepository.findByEmailAndType(email, otpType);

            for (OTP otp : activeOtps) {
                if (!otp.isUsed() && otp.getExpiryTime().isAfter(LocalDateTime.now())) {
                    otp.setUsed(true);
                    otpRepository.save(otp);
                    invalidatedCount++;
                }
            }

            if (invalidatedCount > 0) {
                log.info("Invalidated {} active OTPs for email: {} and type: {}",
                        invalidatedCount, email, otpType);
            }
        } catch (Exception e) {
            log.error("Error invalidating active OTPs for email {}: {}", email, e.getMessage());
        }
    }

    private String generateOtpCode() {
        StringBuilder otp = new StringBuilder();
        for (int i = 0; i < otpLength; i++) {
            otp.append(secureRandom.nextInt(10));
        }
        return otp.toString();
    }

    // ===== VALIDATION METHODS =====

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
            throw new IllegalArgumentException("OTP type cannot be null or empty");
        }

        try {
            return OTPType.valueOf(type.toUpperCase().trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid OTP type: " + type +
                    ". Must be SIGNUP_VERIFICATION, PASSWORD_RESET, or EMAIL_VERIFICATION");
        }
    }

    private String validateOtpCode(String otp) {
        if (!StringUtils.hasText(otp)) {
            throw new IllegalArgumentException("OTP code cannot be null or empty");
        }

        String trimmed = otp.trim();

        if (!trimmed.matches("^\\d{6}$")) {
            throw new IllegalArgumentException("OTP must be exactly 6 digits");
        }

        return trimmed;
    }

    // ===== CLEANUP METHODS =====

    @Scheduled(fixedRate = 600000) // Every 10 minutes
    public void cleanupExpiredOtps() {
        try {
            LocalDateTime currentTime = LocalDateTime.now();
            LocalDateTime cutoffTime = currentTime.minusHours(1);
            int deletedCount = otpRepository.deleteExpiredAndUsedOtps(currentTime, cutoffTime);

            if (deletedCount > 0) {
                log.debug("Cleaned up {} expired and used OTPs", deletedCount);
            }
        } catch (Exception e) {
            log.error("Failed to cleanup expired OTPs: {}", e.getMessage());
        }
    }

    // ===== DTO CLASSES =====

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
