package com.geekcatalog.api.domain.user.useCase;

import com.geekcatalog.api.domain.user.UserRepository;
import com.geekcatalog.api.domain.user.validation.UserValidator;
import com.geekcatalog.api.dto.utils.TokenDTO;
import com.geekcatalog.api.infra.security.TokenService;
import com.geekcatalog.api.service.RefreshTokenLogService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class RefreshAccessTokenIfUserIsEnabled {
    private final UserRepository repository;
    private final UserValidator validator;
    private final TokenService tokenService;
    private final RefreshTokenLogService refreshTokenLogService;

    public TokenDTO updateToken(String refreshToken) {
        if (!tokenService.isRefreshTokenValid(refreshToken)) {
            throw new RuntimeException("Refresh token invalid or expired.");
        }

        var decoded = tokenService.parseClaims(refreshToken);
        var refreshId = decoded.getClaim("refreshId").asString();

        boolean revoked = refreshTokenLogService.isRevoked(refreshId);
        if (revoked) {
            throw new RuntimeException("Refresh token was revoked.");
        }

        var email = tokenService.getSubject(refreshToken);

        var user = repository.findByEmailToHandle(email);

        validator.validateUserExistsAndIsActive(user);

        var novoAccessToken = tokenService.generateAccessToken(user);

        return new TokenDTO(novoAccessToken);
    }
}