package com.geekcatalog.api.domain.refreshTokenLog.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class IsRefreshTokenRevoked {
    @Autowired
    private com.geekcatalog.api.domain.refreshTokenLog.RefreshTokenLogRepository repository;

    public boolean isRevoked(String refreshTokenId) {
        return repository.existsByIdAndRevokedTrue(refreshTokenId);
    }
}
