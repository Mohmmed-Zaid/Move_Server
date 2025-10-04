package com.moveapp.movebackend.service;

import com.moveapp.movebackend.model.enums.OTPType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final SendGridEmailService sendGridEmailService;

    @Value("${move.app.name:MapGuide}")
    private String appName;

    @Async("emailTaskExecutor")
    public CompletableFuture<Boolean> sendOtpEmailAsync(String toEmail, String otpCode, OTPType otpType) {
        try {
            String subject = getOtpEmailSubject(otpType);
            String body = getOtpEmailBody(otpCode, otpType);
            return sendGridEmailService.sendEmail(toEmail, subject, body);
        } catch (Exception e) {
            log.error("Error in sendOtpEmailAsync: {}", e.getMessage());
            return CompletableFuture.completedFuture(false);
        }
    }

    public void sendOtpEmail(String toEmail, String otpCode, OTPType otpType) {
        try {
            CompletableFuture<Boolean> future = sendOtpEmailAsync(toEmail, otpCode, otpType);
            Boolean result = future.get(10, TimeUnit.SECONDS);

            if (!result) {
                throw new RuntimeException("Failed to send email");
            }
            log.info("OTP email sent successfully to: {}", toEmail);
        } catch (TimeoutException e) {
            log.error("Email sending timeout for: {}", toEmail);
            throw new RuntimeException("Email service timeout", e);
        } catch (Exception e) {
            log.error("Failed to send OTP email: {}", e.getMessage());
            throw new RuntimeException("Failed to send email", e);
        }
    }

    @Async("emailTaskExecutor")
    public CompletableFuture<Boolean> sendWelcomeEmailAsync(String toEmail, String userName) {
        try {
            String subject = "Welcome to " + appName + "!";
            String body = buildWelcomeEmailBody(userName);
            return sendGridEmailService.sendEmail(toEmail, subject, body);
        } catch (Exception e) {
            log.error("Error in sendWelcomeEmailAsync: {}", e.getMessage());
            return CompletableFuture.completedFuture(false);
        }
    }

    public void sendWelcomeEmail(String toEmail, String userName) {
        try {
            sendWelcomeEmailAsync(toEmail, userName).get(10, TimeUnit.SECONDS);
            log.info("Welcome email sent to: {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send welcome email: {}", e.getMessage());
        }
    }

    @Async("emailTaskExecutor")
    public CompletableFuture<Boolean> sendPasswordResetConfirmationEmailAsync(String toEmail) {
        try {
            String subject = "Password Reset Confirmation";
            String body = buildPasswordResetConfirmationBody();
            return sendGridEmailService.sendEmail(toEmail, subject, body);
        } catch (Exception e) {
            log.error("Error in sendPasswordResetConfirmationEmailAsync: {}", e.getMessage());
            return CompletableFuture.completedFuture(false);
        }
    }

    public void sendPasswordResetConfirmationEmail(String toEmail) {
        try {
            sendPasswordResetConfirmationEmailAsync(toEmail).get(10, TimeUnit.SECONDS);
            log.info("Password reset confirmation sent to: {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send password reset confirmation: {}", e.getMessage());
        }
    }

    private String getOtpEmailSubject(OTPType otpType) {
        return switch (otpType) {
            case SIGNUP_VERIFICATION -> "Verify your " + appName + " account";
            case PASSWORD_RESET -> "Reset your " + appName + " password";
            case EMAIL_VERIFICATION -> "Verify your email address";
            case LOGIN_VERIFICATION -> "Login verification code";
        };
    }

  private String getOtpEmailBody(String otpCode, OTPType otpType) {
    String purpose = switch (otpType) {
        case SIGNUP_VERIFICATION -> "complete your account registration";
        case PASSWORD_RESET -> "reset your password";
        case EMAIL_VERIFICATION -> "verify your email address";
        case LOGIN_VERIFICATION -> "verify your login";
    };

    return String.format("""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>MapGuide Verification Code</title>
        </head>
        <body style="margin: 0; padding: 0; background: #f0f7ff; font-family: 'Segoe UI', Arial, sans-serif;">
            <div style="min-height: 100vh; padding: 20px;">
                <div style="max-width: 600px; margin: 20px auto; background: #ffffff; border-radius: 20px; box-shadow: 0 10px 30px rgba(0, 50, 150, 0.1); overflow: hidden;">
                    
                    <div style="background: linear-gradient(135deg, #0072ff 0%%, #004bb3 100%%); padding: 40px 30px; text-align: center;">
                        <h1 style="color: white; margin: 0; font-size: 28px; font-weight: 700;">MapGuide</h1>
                        <p style="color: rgba(255, 255, 255, 0.9); font-size: 16px; margin: 10px 0 0 0;">Secure Access Required</p>
                    </div>

                    <div style="padding: 40px 30px; text-align: center;">
                        <h2 style="color: #1a1a1a; margin: 0 0 15px 0; font-size: 24px; font-weight: 600;">
                            Your one-time code to %s
                        </h2>
                        <p style="color: #555; font-size: 16px; line-height: 1.5; margin: 0;">
                            Please enter this code to continue.
                        </p>

                        <div style="background: #f8faff; border: 2px solid #0072ff; border-radius: 15px; padding: 20px 30px; margin: 30px 0; display: inline-block; box-shadow: 0 8px 16px rgba(0, 114, 255, 0.15);">
                            <p style="color: #0072ff; font-size: 14px; font-weight: 600; margin: 0 0 10px 0; text-transform: uppercase;">
                                Verification Code
                            </p>
                            <h1 style="color: #0072ff; font-size: 42px; margin: 0; letter-spacing: 8px; font-weight: 700;">%s</h1>
                        </div>

                        <div style="background: #fff3e6; border: 1px solid #ff9933; border-radius: 10px; padding: 15px; margin-top: 30px; text-align: left;">
                            <p style="color: #ff9933; margin: 0; font-size: 14px; line-height: 1.5;">
                                <strong>Important:</strong> This code is valid for only 5 minutes.
                            </p>
                            <p style="color: #ff9933; margin: 10px 0 0 0; font-size: 14px; line-height: 1.5;">
                                <strong>Security Notice:</strong> If you did not request this, please ignore this email.
                            </p>
                        </div>
                    </div>

                    <div style="background: #f8faff; padding: 20px 30px; text-align: center; border-top: 1px solid #e6ecf2;">
                        <p style="color: #666; font-size: 12px; margin: 0 0 5px 0;">This is an automated message from MapGuide. Please do not reply.</p>
                        <p style="color: #999; font-size: 10px; margin: 0;">&copy; 2025 MapGuide. All rights reserved.</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """, purpose, otpCode);
}
    private String buildWelcomeEmailBody(String userName) {
        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Welcome to MapGuide</title>
            </head>
            <body style="margin: 0; padding: 0; background: #f0f7ff; font-family: Arial, sans-serif;">
                <div style="min-height: 100vh; padding: 20px;">
                    <div style="max-width: 600px; margin: 20px auto; background: #ffffff; border-radius: 20px; padding: 40px;">
                        <h1 style="color: #0072ff; text-align: center; margin-bottom: 20px;">Welcome to MapGuide!</h1>
                        <h2 style="color: #1a1a1a;">Hello %s,</h2>
                        <p style="color: #555; font-size: 16px; line-height: 1.6;">
                            Thank you for joining <strong style="color: #0072ff;">MapGuide</strong>! Your account is ready to use.
                        </p>
                        <p style="color: #555; font-size: 16px; line-height: 1.6;">
                            Start exploring the best routes and navigation features today!
                        </p>
                        <div style="text-align: center; margin-top: 30px;">
                            <p style="color: #0072ff; font-weight: 600;">Happy navigating!</p>
                            <p style="color: #0072ff; font-weight: 700; font-size: 18px;">The MapGuide Team</p>
                        </div>
                    </div>
                </div>
            </body>
            </html>
            """.formatted(userName);
    }

    private String buildPasswordResetConfirmationBody() {
        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0;">
                <title>Password Reset Confirmation</title>
            </head>
            <body style="margin: 0; padding: 0; background: #f0f7ff; font-family: Arial, sans-serif;">
                <div style="min-height: 100vh; padding: 20px;">
                    <div style="max-width: 600px; margin: 20px auto; background: #ffffff; border-radius: 20px; padding: 40px;">
                        <h1 style="color: #0072ff; text-align: center;">MapGuide</h1>
                        <h2 style="color: #28a745; text-align: center;">Password Successfully Changed</h2>
                        <p style="color: #555; font-size: 16px; line-height: 1.6;">
                            Your password for your MapGuide account has been successfully updated.
                        </p>
                        <p style="color: #555; font-size: 16px; line-height: 1.6;">
                            You can now log in to your account with your new password.
                        </p>
                        <div style="background: #f8faff; border-radius: 10px; padding: 20px; margin-top: 20px;">
                            <p style="color: #666; font-size: 14px; margin: 0;">
                                If you did not make this change, please contact support immediately.
                            </p>
                        </div>
                    </div>
                </div>
            </body>
            </html>
            """;
    }
}
