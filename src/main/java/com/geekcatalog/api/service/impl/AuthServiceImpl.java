package com.geekcatalog.api.service.impl;

import com.geekcatalog.api.domain.user.UseCase.*;
import com.geekcatalog.api.dto.user.*;
import com.geekcatalog.api.dto.utils.AuthTokensDTO;
import com.geekcatalog.api.dto.utils.MessageResponseDTO;
import com.geekcatalog.api.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final CreateUser createUser;
    private final DeleteUser deleteUser;
    private final ForgotPassword forgotPassword;
    private final GetPublicInfo getPublicInfo;
    private final GetUserByTokenJWT getUserByTokenJWT;
    private final PerformLogin performLogin;
    private final ResetPassword resetPassword;
    private final UpdateUser updateUser;

    @Override
    public void deleteUser(String userId) {
        deleteUser.deleteUser(userId);
    }

    @Override
    public MessageResponseDTO forgotPassword(UserOnlyEmailDTO data) {
        return forgotPassword.forgotPassword(data);
    }

    @Override
    public UserPublicReturnDTO getPublicInfoByUserId(String userId) {
        return getPublicInfo.getPublicInfoByUserId(userId);
    }

    @Override
    public MessageResponseDTO resetPassword(UserResetPassDTO data) {
        return resetPassword.resetPassword(data);
    }

    @Override
    public AuthTokensDTO signIn(UserLoginDTO data, HttpServletRequest request) {
        return performLogin.performLogin(data, request);
    }

    @Override
    public UserReturnDTO signUp(UserDTO data) {
        return createUser.signUp(data);
    }

    @Override
    public UserReturnDTO updateUserInfo(UserUpdateDTO dto, String tokenJWT) {
        return updateUser.updateUserInfo(dto, tokenJWT);
    }
}
