package com.moveapp.movebackend.service;

import com.sendgrid.*;
import com.sendgrid.helpers.mail.Mail;
import com.sendgrid.helpers.mail.objects.Content;
import com.sendgrid.helpers.mail.objects.Email;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;

@Service
@Slf4j
public class SendGridEmailService {

    @Value("${sendgrid.api.key}")
    private String sendGridApiKey;

    @Value("${sendgrid.from.email}")
    private String fromEmail;

    @Value("${sendgrid.from.name}")
    private String fromName;

    @Async("emailTaskExecutor")
    public CompletableFuture<Boolean> sendEmail(String toEmail, String subject, String htmlContent) {
        try {
            log.info("Sending email via SendGrid to: {}", toEmail);
            
            Email from = new Email(fromEmail, fromName);
            Email to = new Email(toEmail);
            Content content = new Content("text/html", htmlContent);
            Mail mail = new Mail(from, subject, to, content);

            SendGrid sg = new SendGrid(sendGridApiKey);
            Request request = new Request();
            
            request.setMethod(Method.POST);
            request.setEndpoint("mail/send");
            request.setBody(mail.build());
            
            Response response = sg.api(request);
            
            if (response.getStatusCode() >= 200 && response.getStatusCode() < 300) {
                log.info("SendGrid email sent successfully to: {} with status: {}", toEmail, response.getStatusCode());
                return CompletableFuture.completedFuture(true);
            } else {
                log.error("SendGrid failed with status: {} for email: {}", response.getStatusCode(), toEmail);
                log.error("SendGrid response body: {}", response.getBody());
                return CompletableFuture.completedFuture(false);
            }
            
        } catch (IOException e) {
            log.error("IOException while sending email via SendGrid to: {}", toEmail, e);
            return CompletableFuture.completedFuture(false);
        } catch (Exception e) {
            log.error("Unexpected error sending email via SendGrid to: {}", toEmail, e);
            return CompletableFuture.completedFuture(false);
        }
    }
}
