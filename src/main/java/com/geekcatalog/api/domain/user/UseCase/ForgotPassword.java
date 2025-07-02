package com.geekcatalog.api.domain.user.UseCase;

import com.geekcatalog.api.infra.utils.mail.GenerateTokenForgetPassword;
import com.geekcatalog.api.infra.utils.mail.MailDTO;
import com.geekcatalog.api.infra.utils.mail.MailSenderMime;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.infra.exceptions.ValidationException;
import com.geekcatalog.api.domain.user.DTO.UserForgotDTO;
import com.geekcatalog.api.domain.user.DTO.UserOnlyLoginDTO;
import com.geekcatalog.api.domain.user.UserRepository;

import java.time.LocalDateTime;

@Component
public class ForgotPassword {
    @Autowired
    private UserRepository repository;
    @Autowired
    private GenerateTokenForgetPassword mailToken;
    @Autowired
    private MailSenderMime mailSender;

    public void forgotPassword(UserOnlyLoginDTO data) {
        var login = data.login();
        var userExists = repository.existsByLogin(login);

        if (!userExists) {
            throw new ValidationException("No user was found for the provided login");
        }

        var token = mailToken.generateEmailToken();
        var inOneHour = LocalDateTime.now().plusHours(1);
        var forgotDTO = new UserForgotDTO(token, inOneHour);

        var user = repository.findByLoginToHandle(login);
        user.forgotPassword(forgotDTO);

        var subject = "Forgot Password - Geek Catalog";

        var mailDTO = new MailDTO(subject, login, token);

        mailSender.sendMail(mailDTO);
    }
}