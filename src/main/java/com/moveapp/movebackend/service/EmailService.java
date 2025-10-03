package com.moveapp.movebackend.service;

import com.moveapp.movebackend.model.enums.OTPType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username:noreply@moveapp.com}")
    private String fromEmail;

    @Value("${move.app.name:Move App}")
    private String appName;

    @Async("emailTaskExecutor")
    public CompletableFuture<Boolean> sendOtpEmailAsync(String toEmail, String otpCode, OTPType otpType) {
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(toEmail);

            String subject = getOtpEmailSubject(otpType);
            String body = getOtpEmailBody(otpCode, otpType);

            helper.setSubject(subject);
            helper.setText(body, true);

            mailSender.send(mimeMessage);
            log.info("OTP email sent successfully to: {}", toEmail);
            return CompletableFuture.completedFuture(true);

        } catch (MessagingException e) {
            log.error("Failed to send OTP email to: {}", toEmail, e);
            return CompletableFuture.completedFuture(false);
        } catch (Exception e) {
            log.error("Unexpected error sending OTP email to: {}", toEmail, e);
            return CompletableFuture.completedFuture(false);
        }
    }

    public void sendOtpEmail(String toEmail, String otpCode, OTPType otpType) {
        try {
            CompletableFuture<Boolean> future = sendOtpEmailAsync(toEmail, otpCode, otpType);
            Boolean result = future.get(5, TimeUnit.SECONDS);
            
            if (!result) {
                throw new RuntimeException("Failed to send email");
            }
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
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(toEmail);
            helper.setSubject("Welcome to " + appName + "!");

            String body = buildWelcomeEmailBody(userName);
            helper.setText(body, true);

            mailSender.send(mimeMessage);
            log.info("Welcome email sent successfully to: {}", toEmail);
            return CompletableFuture.completedFuture(true);

        } catch (Exception e) {
            log.error("Failed to send welcome email to: {}", toEmail, e);
            return CompletableFuture.completedFuture(false);
        }
    }

    public void sendWelcomeEmail(String toEmail, String userName) {
        try {
            sendWelcomeEmailAsync(toEmail, userName).get(5, TimeUnit.SECONDS);
        } catch (Exception e) {
            log.error("Failed to send welcome email: {}", e.getMessage());
        }
    }

    @Async("emailTaskExecutor")
    public CompletableFuture<Boolean> sendPasswordResetConfirmationEmailAsync(String toEmail) {
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(toEmail);
            helper.setSubject("Password Reset Confirmation");

            String body = buildPasswordResetConfirmationBody();
            helper.setText(body, true);

            mailSender.send(mimeMessage);
            log.info("Password reset confirmation email sent to: {}", toEmail);
            return CompletableFuture.completedFuture(true);

        } catch (Exception e) {
            log.error("Failed to send password reset confirmation email to: {}", toEmail, e);
            return CompletableFuture.completedFuture(false);
        }
    }

    public void sendPasswordResetConfirmationEmail(String toEmail) {
        try {
            sendPasswordResetConfirmationEmailAsync(toEmail).get(5, TimeUnit.SECONDS);
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

        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>MapGuide Verification Code</title>
                <style>
                    body { font-family: 'Inter', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
                </style>
            </head>
            <body style="margin: 0; padding: 0; background: #f0f7ff;">
                <div style="min-height: 100vh; padding: 20px; font-family: 'Inter', sans-serif;">
                    <div style="max-width: 600px; margin: 20px auto; background: #ffffff; border-radius: 20px; box-shadow: 0 10px 30px rgba(0, 50, 150, 0.1); overflow: hidden;">
                        
                        <div style="background: linear-gradient(135deg, #0072ff 0%%, #004bb3 100%%); padding: 40px 30px; text-align: center;">
                            <h1 style="color: white; margin: 0; font-size: 28px; font-weight: 700; text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);">
                                MapGuide
                            </h1>
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
            """.formatted(purpose, otpCode);
    }

    private String buildWelcomeEmailBody(String userName) {
        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Welcome to MapGuide</title>
                <style>
                    body { font-family: 'Inter', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
                </style>
            </head>
            <body style="margin: 0; padding: 0; background: #f0f7ff;">
                <div style="min-height: 100vh; padding: 20px; font-family: 'Inter', sans-serif;">
                    <div style="max-width: 600px; margin: 20px auto; background: #ffffff; border-radius: 20px; box-shadow: 0 10px 30px rgba(0, 50, 150, 0.1); overflow: hidden;">
                        
                        <div style="background: linear-gradient(135deg, #0072ff 0%%, #004bb3 100%%); padding: 40px 30px; text-align: center;">
                            <h1 style="color: white; margin: 0; font-size: 32px; font-weight: 700; text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);">
                                WELCOME TO MAPGUIDE
                            </h1>
                            <p style="color: rgba(255, 255, 255, 0.9); font-size: 16px; margin: 10px 0 0 0;">Your journey begins now</p>
                        </div>

                        <div style="padding: 40px 30px; text-align: center;">
                            <h2 style="color: #1a1a1a; margin: 0 0 15px 0; font-size: 26px; font-weight: 600;">Hello %s!</h2>
                            <p style="color: #555; font-size: 16px; line-height: 1.6; margin: 0;">
                                Thank you for joining <strong style="color: #0072ff;">MapGuide</strong>! Your account is ready to go.
                            </p>

                            <div style="background: #f8faff; border-radius: 15px; padding: 25px; margin: 30px 0;">
                                <h3 style="color: #0072ff; margin: 0 0 20px 0; font-size: 20px; font-weight: 600;">Key Features</h3>
                                <div style="text-align: left;">
                                    <p style="margin: 10px 0; color: #333; font-size: 15px;">
                                        <strong>Real-time Navigation:</strong> Get the best routes with live traffic.
                                    </p>
                                    <p style="margin: 10px 0; color: #333; font-size: 15px;">
                                        <strong>Location Sharing:</strong> Easily share your location with friends and family.
                                    </p>
                                    <p style="margin: 10px 0; color: #333; font-size: 15px;">
                                        <strong>Route Planning:</strong> Plan multi-stop trips and optimize your journey.
                                    </p>
                                </div>
                            </div>
                        </div>

                        <div style="background: #f8faff; padding: 30px; text-align: center; border-top: 1px solid #e6ecf2;">
                            <p style="color: #0072ff; font-size: 16px; margin: 0 0 10px 0; font-weight: 600;">Happy navigating!</p>
                            <p style="color: #0072ff; font-size: 18px; margin: 0 0 20px 0; font-weight: 700;">The MapGuide Team</p>
                            <p style="color: #999; font-size: 10px; margin: 0;">&copy; 2025 MapGuide. All rights reserved.</p>
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
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Password Reset Confirmation</title>
                <style>
                    body { font-family: 'Inter', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
                </style>
            </head>
            <body style="margin: 0; padding: 0; background: #f0f7ff;">
                <div style="min-height: 100vh; padding: 20px; font-family: 'Inter', sans-serif;">
                    <div style="max-width: 600px; margin: 20px auto; background: #ffffff; border-radius: 20px; box-shadow: 0 10px 30px rgba(0, 50, 150, 0.1); overflow: hidden;">
                        
                        <div style="background: linear-gradient(135deg, #0072ff 0%%, #004bb3 100%%); padding: 40px 30px; text-align: center;">
                            <h1 style="color: white; margin: 0; font-size: 28px; font-weight: 700; text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);">
                                MapGuide
                            </h1>
                            <p style="color: rgba(255, 255, 255, 0.9); font-size: 16px; margin: 10px 0 0 0;">Password Reset Complete</p>
                        </div>

                        <div style="padding: 40px 30px; text-align: center;">
                            <div style="margin-bottom: 25px;">
                                <h2 style="color: #28a745; margin: 0 0 10px 0; font-size: 24px; font-weight: 600;">
                                    Password Successfully Changed
                                </h2>
                                <p style="color: #555; font-size: 16px; line-height: 1.5; margin: 0;">
                                    Your password for your MapGuide account has been successfully updated.
                                </p>
                            </div>

                            <div style="background: #f8faff; border-radius: 15px; padding: 25px; margin: 30px 0;">
                                <h3 style="color: #0072ff; margin: 0 0 20px 0; font-size: 20px; font-weight: 600;">
                                    Security Recommendations
                                </h3>
                                <div style="text-align: left; color: #555; font-size: 15px;">
                                    <p style="margin: 10px 0;"><strong>Unique Password:</strong> Use a strong, unique password for every service.</p>
                                    <p style="margin: 10px 0;"><strong>Two-Factor Auth:</strong> Enable 2FA for an extra layer of security.</p>
                                    <p style="margin: 10px 0;"><strong>Be Alert:</strong> Report any suspicious activity to our support team.</p>
                                </div>
                            </div>
                        </div>

                        <div style="background: #f8faff; padding: 20px 30px; text-align: center; border-top: 1px solid #e6ecf2;">
                            <p style="color: #666; font-size: 12px; margin: 0 0 5px 0;">This is an automated email from MapGuide. Please do not reply.</p>
                            <p style="color: #999; font-size: 10px; margin: 0;">&copy; 2025 MapGuide. All rights reserved.</p>
                        </div>
                    </div>
                </div>
            </body>
            </html>
            """;
    }
}
