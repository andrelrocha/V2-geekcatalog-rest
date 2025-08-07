package com.geekcatalog.api.domain.user.UseCase;

import com.geekcatalog.api.domain.user.User;
import com.geekcatalog.api.domain.user.validation.UserValidator;
import com.geekcatalog.api.dto.user.UserSignInDTO;
import com.geekcatalog.api.dto.utils.AuthTokensDTO;
import com.geekcatalog.api.domain.auditLogLogin.LoginStatus;
import com.geekcatalog.api.domain.auditLogLogin.useCase.RegisterAuditLog;
import com.geekcatalog.api.infra.security.TokenService;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
public class PerformLogin {

    private final AuthenticationManager manager;
    private final TokenService tokenService;
    private final RegisterAuditLog registerAuditLog;
    private final UpdateUserFailedLogin updateUserFailedLogin;
    private final UserValidator validator;

    @Transactional
    public AuthTokensDTO login(UserSignInDTO data, HttpServletRequest request) {
        validator.validateCredentialsInformed(data.login(), data.password());

        var authenticationToken = new UsernamePasswordAuthenticationToken(data.login(), data.password());

        try {
            Authentication authentication = manager.authenticate(authenticationToken);
            User userAuthenticated = (User) authentication.getPrincipal();

            userAuthenticated.resetAccessCount();

            String accessToken = tokenService.generateAccessToken(userAuthenticated);
            String refreshToken = null;
            if (userAuthenticated.isRefreshTokenEnabled()) {
                refreshToken = tokenService.generateRefreshToken(userAuthenticated);
            }

            registerAuditLog.logLogin(
                    data.login(),
                    request,
                    LoginStatus.SUCCESS,
                    request.getHeader("User-Agent")
            );

            return new AuthTokensDTO(accessToken, refreshToken);

        } catch (BadCredentialsException e) {
            handleFailedLogin(data.login(), request);
            throw new BadCredentialsException("Wrong login or password.");
        }
    }

    @Transactional
    private void handleFailedLogin(String login, HttpServletRequest request) {
        updateUserFailedLogin.updateFailedLogin(login);

        registerAuditLog.logLogin(
                login,
                request,
                LoginStatus.FAILURE,
                request.getHeader("User-Agent")
        );
    }
}
