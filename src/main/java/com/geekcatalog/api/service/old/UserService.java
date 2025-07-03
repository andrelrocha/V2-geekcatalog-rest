package com.geekcatalog.api.service.old;

import com.geekcatalog.api.domain.user.DTO.*;
import com.geekcatalog.api.dto.user.*;
import com.geekcatalog.api.dto.utils.AuthTokensDTO;
import jakarta.servlet.http.HttpServletRequest;

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
