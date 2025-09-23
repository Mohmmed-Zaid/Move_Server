package com.moveapp.movebackend.service;

import com.moveapp.movebackend.model.dto.AuthenticationDto.*;
import com.moveapp.movebackend.model.dto.OTPdto.*;
import com.moveapp.movebackend.model.entities.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;

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

    // OAuth methods
    User createOrUpdateOAuthUser(String email, String name, String avatarUrl, Authentication authentication);
    AuthResponse linkOAuthAccount(String email, Authentication oauthAuthentication);
    AuthResponse handleOAuth2Success(OAuth2User oauth2User, Authentication authentication);
}