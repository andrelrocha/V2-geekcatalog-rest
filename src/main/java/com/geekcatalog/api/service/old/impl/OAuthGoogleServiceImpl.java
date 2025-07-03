package com.geekcatalog.api.service.old.impl;

import com.geekcatalog.api.dto.utils.AuthTokensDTO;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.geekcatalog.api.domain.user.UseCase.AuthenticateGoogleUser;
import com.geekcatalog.api.infra.utils.oauth.ExchangeCodeForAccessToken;
import com.geekcatalog.api.service.old.OAuthGoogleService;

@Service
public class OAuthGoogleServiceImpl implements OAuthGoogleService {
    @Autowired
    private AuthenticateGoogleUser authenticateGoogleUser;
    @Autowired
    private ExchangeCodeForAccessToken exchangeCodeForAccessToken;

    public String exchangeCodeForAccessToken(String code) {
        return exchangeCodeForAccessToken.exchangeCodeForAccessToken(code);
    }

    @Override
    public AuthTokensDTO signInGoogleUser(String googleAccessToken, HttpServletRequest request) {
        return authenticateGoogleUser.signInGoogleUser(googleAccessToken, request);
    }
}
