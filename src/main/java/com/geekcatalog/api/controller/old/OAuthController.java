package com.geekcatalog.api.controller.old;

import com.geekcatalog.api.dto.utils.AccessTokenDTO;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.geekcatalog.api.infra.utils.oauth.google.GoogleAccessToken;
import com.geekcatalog.api.infra.utils.httpCookies.CookieManager;
import com.geekcatalog.api.service.old.OAuthGoogleService;


@RestController
@RequestMapping("/oauth")
@Tag(name = "OAuth Routes Mapped on Controller")
public class OAuthController {
    @Autowired
    private CookieManager cookieManager;
    @Autowired
    private OAuthGoogleService oAuthGoogleService;

    @GetMapping("/google")
    public ResponseEntity<GoogleAccessToken> handleGoogleLogin(@RequestParam String code) {
        String accessToken = oAuthGoogleService.exchangeCodeForAccessToken(code);
        var googleAccessToken = new GoogleAccessToken(accessToken);
        return ResponseEntity.ok(googleAccessToken);
    }

    @GetMapping("/googlelogin")
    public ResponseEntity<AccessTokenDTO> authenticateGoogleUser(@RequestHeader("Authorization") String authorizationHeader, HttpServletResponse response, HttpServletRequest request) {
        var googleAccessToken = authorizationHeader.substring(7);
        var authTokens = oAuthGoogleService.signInGoogleUser(googleAccessToken, request);
        if (authTokens.refreshToken() != null) {
            cookieManager.addRefreshTokenCookie(response, authTokens.refreshToken());
        }
        AccessTokenDTO accessTokenDto = new AccessTokenDTO(authTokens.accessToken());
        return ResponseEntity.ok(accessTokenDto);
    }
}
