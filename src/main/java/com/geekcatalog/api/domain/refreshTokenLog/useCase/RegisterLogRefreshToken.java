package com.geekcatalog.api.domain.refreshTokenLog.useCase;

import com.geekcatalog.api.domain.refreshTokenLog.RefreshTokenLog;
import com.geekcatalog.api.domain.refreshTokenLog.RefreshTokenLogRepository;
import com.geekcatalog.api.domain.user.User;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
public class RegisterLogRefreshToken {
    private final RefreshTokenLogRepository repository;

    @Transactional
    public void register(User user, String refreshTokenId, LocalDateTime issuedAt, LocalDateTime expiresAt, HttpServletRequest request) {
        var log = new RefreshTokenLog();

        log.setUser(user);
        log.setRefreshTokenId(refreshTokenId);
        log.setIssuedAt(issuedAt);
        log.setExpiresAt(expiresAt);
        log.setUserAgent(request.getHeader("User-Agent"));
        log.setIpAddress(request.getRemoteAddr());
        log.setRevoked(false);

        repository.save(log);
    }
}
