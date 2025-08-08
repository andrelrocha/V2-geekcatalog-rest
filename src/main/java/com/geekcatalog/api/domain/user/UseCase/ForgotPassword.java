package com.geekcatalog.api.domain.user.useCase;

import com.geekcatalog.api.domain.user.validation.UserValidator;
import com.geekcatalog.api.dto.user.UserOnlyEmailDTO;
import com.geekcatalog.api.dto.utils.MessageResponseDTO;
import com.geekcatalog.api.infra.utils.mail.*;
import com.geekcatalog.api.dto.utils.MailDTO;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.infra.exceptions.EmailSendingException;
import com.geekcatalog.api.dto.user.UserForgotDTO;
import com.geekcatalog.api.domain.user.UserRepository;

import java.time.LocalDateTime;

@Component
@AllArgsConstructor
public class ForgotPassword {
    private final UserRepository repository;
    private final UserValidator validator;
    private final GenerateTokenForgetPassword mailToken;
    private final MailSenderMime mailSender;

    @Transactional
    public MessageResponseDTO forgotPassword(UserOnlyEmailDTO data) {
        validator.validateEmailExists(data.email());

        var token = mailToken.generateEmailToken();
        var inOneHour = LocalDateTime.now().plusHours(1);
        var forgotDTO = new UserForgotDTO(token, inOneHour);

        var user = repository.findByEmailToHandle(data.email());
        user.forgotPassword(forgotDTO);

        var mailDTO = getMailDTO(data.email(), token);

        try {
            mailSender.sendMail(mailDTO);
            return new MessageResponseDTO("Successfully sent the email with password reset instructions.");
        } catch (Exception e) {
            throw new EmailSendingException("Error while sending the email with password reset instructions.", e);
        }

    }

    @NotNull
    private static MailDTO getMailDTO(String email, String token) {
        var subject = "Forgot Password - Geek Catalog";

        var body = """
                Hello %s,

                We received a request to reset the password for your account on GeekCatalog.
        
                To proceed with the password reset, please use the token below in the application:
        
                Reset Token: %s
        
                This token is valid for 1 hour and should only be used on the official platform. 
                For security reasons, do not share this code with anyone. 
                The GeekCatalog team will never ask for this token via email or any other communication method.
        
                If you did not request this password reset, please disregard this email.
        
                Sincerely,  
                The GeekCatalog Team
                """.formatted(email, token);


        return new MailDTO(subject, email, body);
    }
}