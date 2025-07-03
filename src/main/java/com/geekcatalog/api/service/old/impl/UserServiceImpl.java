package com.geekcatalog.api.service.old.impl;

import com.geekcatalog.api.domain.user.DTO.*;
import com.geekcatalog.api.domain.user.UseCase.*;
import com.geekcatalog.api.dto.user.*;
import com.geekcatalog.api.dto.utils.AuthTokensDTO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.geekcatalog.api.service.old.UserService;

@Service
@Transactional
public class UserServiceImpl implements UserService {
    @Autowired
    private CreateUser createUser;
    @Autowired
    private DeleteUser deleteUser;
    @Autowired
    private GetUserByTokenJWT getUserByTokenJWT;
    @Autowired
    private GetUserIdByJWT getUserIdByJWT;
    @Autowired
    private GetPublicInfo getPublicInfo;
    @Autowired
    private ForgotPassword forgotPassword;
    @Autowired
    private PerformLogin performLogin;
    @Autowired
    private UpdateUser updateUser;
    @Autowired
    private ResetPassword resetPassword;

    @Override
    public AuthTokensDTO performLogin(UserLoginDTO data, HttpServletRequest request) {
        var tokensJwt = performLogin.performLogin(data, request);
        return tokensJwt;
    }

    @Override
    public UserReturnDTO createUser(UserDTO data) {
        var user = createUser.signUp(data);
        return user;
    }

    @Override
    public UserReturnDTO getUserByTokenJWT(String id) {
        var user = getUserByTokenJWT.getUserByID(id);
        return user;
    }

    @Override
    public String forgotPassword(UserOnlyEmailDTO data) {
        forgotPassword.forgotPassword(data);
        return "Email sent with accessToken for password reset";
    }

    @Override
    public String resetPassword(UserResetPassDTO data) {
        resetPassword.resetPassword(data);
        return "Password successfully updated!";
    }

    @Override
    public UserIdDTO getUserIdByJWT(String token) {
        var userId = getUserIdByJWT.getUserByJWT(token);
        return userId;
    }

    @Override
    public UserReturnDTO updateUserInfo(UserGetInfoUpdateDTO data, String tokenJWT) {
        var updatedUser = updateUser.updateUserInfo(data, tokenJWT);
        return updatedUser;
    }

    @Override
    public void deleteUser(String tokenJWT) {
        deleteUser.deleteUser(tokenJWT);
    }

    @Override
    public UserPublicReturnDTO getPublicInfoByUserId(String userId) {
        return getPublicInfo.getPublicInfoByUserId(userId);
    }
}
