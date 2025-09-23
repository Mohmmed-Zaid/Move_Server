package com.moveapp.movebackend.model.entities;

import com.moveapp.movebackend.model.enums.OTPType;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
@Table(name = "otps")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EntityListeners(AuditingEntityListener.class)
public class OTP {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String email;

    @Column(nullable = false, length = 10)
    private String otpCode;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private OTPType type;

    @Column(nullable = false)
    private LocalDateTime expiryTime;

    // Alternative getter name for compatibility
    public LocalDateTime getExpiresAt() {
        return this.expiryTime;
    }

    public void setExpiresAt(LocalDateTime expiresAt) {
        this.expiryTime = expiresAt;
    }

    @Column(nullable = false)
    @Builder.Default
    private boolean used = false;

    public boolean isUsed() {
        return this.used;
    }

    public void setUsed(boolean used) {
        this.used = used;
    }

    @Column(nullable = false)
    @Builder.Default
    private Integer attempts = 0;

    @Column(nullable = false)
    @Builder.Default
    private Integer maxAttempts = 3;

    @CreatedDate
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    private LocalDateTime updatedAt;

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiryTime);
    }

    public boolean isMaxAttemptsReached() {
        return attempts >= maxAttempts;
    }
}