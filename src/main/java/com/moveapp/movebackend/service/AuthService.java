package com.moveapp.movebackend.service;

import com.moveapp.movebackend.model.dto.AuthenticationDto.*;
import com.moveapp.movebackend.model.dto.OTPdto.*;
import com.moveapp.movebackend.model.entities.User;
import org.springframework.security.core.Authentication;

import java.util.Optional;

public interface AuthService {

    // Authentication methods
    AuthResponse signin(AuthRequest authRequest);
    AuthResponse signup(SignupRequest signupRequest);
    AuthResponse signupWithOtp(SignupWithOtpRequest request);
    void signout(String token);

    // OTP methods
    OtpResponse sendSignupOtp(String email);
    OtpResponse verifySignupOtp(String email, String otp);
    OtpResponse sendPasswordResetOtp(String email);
    OtpResponse verifyPasswordResetOtp(String email, String otp);
    OtpResponse resetPassword(ResetPasswordRequest request);
    OtpResponse verifyOtp(VerifyOtpRequest request);
    OtpResponse verifyEmail(VerifyOtpRequest request);
    OtpResponse sendEmailVerificationOtp(String email);

    // Token management
    AuthResponse refreshToken(String token);

    // User profile management
    Optional<UserDto> getUserByEmail(String email);
    UserDto updateUserProfile(String email, String name, String avatarUrl);
    boolean emailExists(String email);
}