package com.geekcatalog.api.service.impl;

import com.geekcatalog.api.domain.user.UseCase.*;
import com.geekcatalog.api.dto.user.*;
import com.geekcatalog.api.dto.utils.AuthTokensDTO;
import com.geekcatalog.api.dto.utils.MessageResponseDTO;
import com.geekcatalog.api.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AuthServiceImpl implements AuthService {
    @Autowired
    private CreateUser createUser;
    @Autowired
    private DeleteUser deleteUser;
    @Autowired
    private ForgotPassword forgotPassword;
    @Autowired
    private GetPublicInfo getPublicInfo;
    @Autowired
    private GetUserByTokenJWT getUserByTokenJWT;
    @Autowired
    private PerformLogin performLogin;
    @Autowired
    private ResetPassword resetPassword;
    @Autowired
    private UpdateUser updateUser;

    @Override
    public void deleteUser(String tokenJWT) {
        deleteUser.deleteUser(tokenJWT);
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
    public UserReturnDTO getUserByIdClaim(String tokenJWT) {
        return getUserByTokenJWT.getUserByIdClaim(tokenJWT);
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
