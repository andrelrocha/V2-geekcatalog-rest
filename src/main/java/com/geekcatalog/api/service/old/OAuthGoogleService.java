package com.geekcatalog.api.service.old;

import com.geekcatalog.api.dto.utils.AuthTokensDTO;
import jakarta.servlet.http.HttpServletRequest;

public interface OAuthGoogleService {
    String exchangeCodeForAccessToken(String code);
    AuthTokensDTO signInGoogleUser(String googleAccessToken, HttpServletRequest request);
}
