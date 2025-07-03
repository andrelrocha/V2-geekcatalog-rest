package com.geekcatalog.api.service;

import com.geekcatalog.api.domain.user.DTO.*;
import com.geekcatalog.api.dto.user.UserDTO;
import com.geekcatalog.api.dto.user.UserOnlyEmailDTO;
import com.geekcatalog.api.dto.user.UserResetPassDTO;
import com.geekcatalog.api.dto.user.UserReturnDTO;
import jakarta.servlet.http.HttpServletRequest;
import com.geekcatalog.api.infra.security.AuthTokensDTO;

public interface UserService {
    UserReturnDTO createUser(UserDTO data);
    UserReturnDTO getUserByTokenJWT(String id);
    AuthTokensDTO performLogin(UserLoginDTO data, HttpServletRequest request);
    String forgotPassword(UserOnlyEmailDTO data);
    String resetPassword(UserResetPassDTO data);
    UserIdDTO getUserIdByJWT(String token);
    UserReturnDTO updateUserInfo(UserGetInfoUpdateDTO data, String tokenJWT);
    void deleteUser(String tokenJWT);
    UserPublicReturnDTO getPublicInfoByUserId(String userId);
}
