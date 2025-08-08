package com.geekcatalog.api.service;

import com.geekcatalog.api.domain.refreshTokenLog.useCase.IsRefreshTokenRevoked;
import com.geekcatalog.api.domain.refreshTokenLog.useCase.RegisterLogRefreshToken;
import com.geekcatalog.api.domain.refreshTokenLog.useCase.RevokeRefreshToken;
import com.geekcatalog.api.domain.user.User;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class RefreshTokenLogService {
    private final RegisterLogRefreshToken registerLogRefreshToken;
    private final RevokeRefreshToken revokeRefreshToken;
    private final IsRefreshTokenRevoked isRefreshTokenRevoked;

    public boolean isRevoked(String refreshTokenId) {
        return isRefreshTokenRevoked.isRevoked(refreshTokenId);
    }

    public void register(User user, String refreshTokenId, LocalDateTime issuedAt, LocalDateTime expiresAt, HttpServletRequest request) {
        registerLogRefreshToken.register(user, refreshTokenId, issuedAt, expiresAt, request);
    }

    public void revoke(String refreshTokenId) {
        revokeRefreshToken.revokeByRefreshId(refreshTokenId);
    }
}
