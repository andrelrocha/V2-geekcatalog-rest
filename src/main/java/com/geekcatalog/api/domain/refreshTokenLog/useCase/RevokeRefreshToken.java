package com.geekcatalog.api.domain.refreshTokenLog.useCase;

import com.geekcatalog.api.domain.refreshTokenLog.RefreshTokenLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
public class RevokeRefreshToken {
    private final RefreshTokenLogRepository repository;

    @Transactional
    public void revokeByRefreshId(String refreshTokenId) {
        var optionalLog = repository.findByRefreshTokenId(refreshTokenId);
        optionalLog.ifPresent(log -> {
            log.setRevoked(true);
            repository.save(log);
        });
    }
}