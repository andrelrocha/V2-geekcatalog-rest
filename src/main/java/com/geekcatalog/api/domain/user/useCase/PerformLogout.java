package com.geekcatalog.api.domain.user.useCase;

import com.geekcatalog.api.infra.security.TokenService;
import com.geekcatalog.api.infra.utils.httpCookies.CookieManager;
import com.geekcatalog.api.service.RefreshTokenLogService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class PerformLogout {
    private final CookieManager cookieManager;
    private final TokenService tokenService;
    private final RefreshTokenLogService refreshTokenLogService;

    public void logout(HttpServletRequest request, HttpServletResponse response) {
        var refreshToken = cookieManager.getRefreshTokenFromCookie(request);

        if (refreshToken != null && tokenService.isRefreshTokenValid(refreshToken)) {
            var decoded = tokenService.parseClaims(refreshToken);
            var refreshId = decoded.getClaim("refreshId").asString();

            refreshTokenLogService.revoke(refreshId);
        }

        cookieManager.removeRefreshTokenCookie(response);
    }
}