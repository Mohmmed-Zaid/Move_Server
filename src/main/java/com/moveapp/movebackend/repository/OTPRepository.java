package com.moveapp.movebackend.repository;

import com.moveapp.movebackend.model.entities.OTP;
import com.moveapp.movebackend.model.enums.OTPType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface OTPRepository extends JpaRepository<OTP, Long> {

    // This is the method that was missing - finds OTP by email, type and not used
    Optional<OTP> findByEmailAndTypeAndUsedFalse(String email, OTPType type);

    // Find the most recent non-used OTP by email and type
    Optional<OTP> findFirstByEmailAndTypeAndUsedFalseOrderByCreatedAtDesc(String email, OTPType type);

    // Find active OTP by email and type (most recent first)
    @Query("SELECT o FROM OTP o WHERE o.email = :email AND o.type = :type AND o.expiryTime > :currentTime AND o.used = false ORDER BY o.createdAt DESC")
    Optional<OTP> findActiveOtpByEmailAndType(@Param("email") String email,
                                              @Param("type") OTPType type,
                                              @Param("currentTime") LocalDateTime currentTime);

    // Find any active OTP by email (for debugging)
    @Query("SELECT o FROM OTP o WHERE o.email = :email AND o.expiryTime > :currentTime AND o.used = false ORDER BY o.createdAt DESC")
    Optional<OTP> findActiveOtpByEmail(@Param("email") String email,
                                       @Param("currentTime") LocalDateTime currentTime);

    // Find all OTPs by email and type
    List<OTP> findByEmailAndType(String email, OTPType type);

    // Find first OTP by email and type ordered by creation date (most recent first)
    Optional<OTP> findFirstByEmailAndTypeOrderByCreatedAtDesc(String email, OTPType type);

    // Count recent OTPs for rate limiting
    @Query("SELECT COUNT(o) FROM OTP o WHERE o.email = :email AND o.type = :type AND o.createdAt > :timeThreshold")
    Long countRecentOtpsByEmailAndType(@Param("email") String email,
                                       @Param("type") OTPType type,
                                       @Param("timeThreshold") LocalDateTime timeThreshold);

    // Find oldest recent OTP time for rate limiting
    @Query("SELECT MIN(o.createdAt) FROM OTP o WHERE o.email = :email AND o.type = :type AND o.createdAt > :timeThreshold")
    LocalDateTime findOldestRecentOtpTime(@Param("email") String email,
                                          @Param("type") OTPType type,
                                          @Param("timeThreshold") LocalDateTime timeThreshold);

    // Delete expired and used OTPs (cleanup)
    @Modifying
    @Query("DELETE FROM OTP o WHERE (o.expiryTime < :currentTime) OR (o.used = true AND o.updatedAt < :cutoffTime)")
    int deleteExpiredAndUsedOtps(@Param("currentTime") LocalDateTime currentTime,
                                 @Param("cutoffTime") LocalDateTime cutoffTime);

    // Find all OTPs by email (for status checking)
    List<OTP> findByEmailOrderByCreatedAtDesc(String email);

    // Check if OTP exists and is valid
    @Query("SELECT COUNT(o) > 0 FROM OTP o WHERE o.email = :email AND o.type = :type AND o.otpCode = :otpCode AND o.expiryTime > :currentTime AND o.used = false")
    boolean existsValidOtp(@Param("email") String email,
                           @Param("type") OTPType type,
                           @Param("otpCode") String otpCode,
                           @Param("currentTime") LocalDateTime currentTime);

    // Find recent used OTPs for verification status
    @Query("SELECT o FROM OTP o WHERE o.email = :email AND o.type = :type AND o.used = true AND o.updatedAt > :recentTime ORDER BY o.updatedAt DESC")
    List<OTP> findRecentUsedOtps(@Param("email") String email,
                                 @Param("type") OTPType type,
                                 @Param("recentTime") LocalDateTime recentTime);
}