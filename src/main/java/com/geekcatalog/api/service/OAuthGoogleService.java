package com.geekcatalog.api.service;

import jakarta.servlet.http.HttpServletRequest;
import com.geekcatalog.api.infra.security.AuthTokensDTO;

public interface OAuthGoogleService {
    String exchangeCodeForAccessToken(String code);
    AuthTokensDTO signInGoogleUser(String googleAccessToken, HttpServletRequest request);
}
