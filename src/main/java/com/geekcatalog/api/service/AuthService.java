package com.geekcatalog.api.service;

import com.geekcatalog.api.domain.user.UseCase.*;
import com.geekcatalog.api.dto.user.*;
import com.geekcatalog.api.dto.utils.AuthTokensDTO;
import com.geekcatalog.api.dto.utils.MessageResponseDTO;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final DeleteUser deleteUser;
    private final ForgotPassword forgotPassword;
    private final GetPublicInfo getPublicInfo;
    private final GetUserByTokenJWT getUserByTokenJWT;
    private final PerformLogin performLogin;
    private final ResetPassword resetPassword;

    public void deleteUser(String userId) {
        deleteUser.deleteUser(userId);
    }

    public MessageResponseDTO forgotPassword(UserOnlyEmailDTO data) {
        return forgotPassword.forgotPassword(data);
    }

    public UserPublicReturnDTO getPublicInfoByUserId(String userId) {
        return getPublicInfo.getPublicInfoByUserId(userId);
    }

    public MessageResponseDTO resetPassword(UserResetPassDTO data) {
        return resetPassword.resetPassword(data);
    }

    public AuthTokensDTO signIn(UserSignInDTO data, HttpServletRequest request) {
        return performLogin.login(data, request);
    }


}
