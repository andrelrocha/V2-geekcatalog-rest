package com.geekcatalog.api.service;

import com.geekcatalog.api.domain.user.useCase.*;
import com.geekcatalog.api.dto.user.UserOnlyEmailDTO;
import com.geekcatalog.api.dto.user.UserResetPassDTO;
import com.geekcatalog.api.dto.user.UserSignInDTO;
import com.geekcatalog.api.dto.utils.AuthTokensDTO;
import com.geekcatalog.api.dto.utils.MessageResponseDTO;
import com.geekcatalog.api.dto.utils.TokenDTO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final ForgotPassword forgotPassword;
    private final PerformLogin performLogin;
    private final PerformLogout performLogout;
    private final RefreshAccessTokenIfUserIsEnabled refreshAccessTokenIfUserIsEnabled;
    private final ResetPassword resetPassword;

    public MessageResponseDTO forgotPassword(UserOnlyEmailDTO data) {
        return forgotPassword.forgotPassword(data);
    }

    public AuthTokensDTO signIn(UserSignInDTO data, HttpServletRequest request) {
        return performLogin.login(data, request);
    }

    public void signOut(HttpServletRequest request, HttpServletResponse response) {
        performLogout.logout(request, response);
    }

    public TokenDTO updateToken(String refreshToken) {
        return refreshAccessTokenIfUserIsEnabled.updateToken(refreshToken);
    }

    public MessageResponseDTO resetPassword(UserResetPassDTO data) {
        return resetPassword.resetPassword(data);
    }
}
