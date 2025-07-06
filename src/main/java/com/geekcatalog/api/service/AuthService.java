package com.geekcatalog.api.service;

import com.geekcatalog.api.dto.user.*;
import com.geekcatalog.api.dto.utils.AuthTokensDTO;
import com.geekcatalog.api.dto.utils.MessageResponseDTO;
import jakarta.servlet.http.HttpServletRequest;

public interface AuthService {
    void deleteUser(String tokenJWT);
    MessageResponseDTO forgotPassword(UserOnlyEmailDTO data);
    UserPublicReturnDTO getPublicInfoByUserId(String userId);
    UserReturnDTO getUserByIdClaim(String tokenJWT);
    MessageResponseDTO resetPassword(UserResetPassDTO data);
    AuthTokensDTO signIn(UserLoginDTO data, HttpServletRequest request);
    UserReturnDTO signUp(UserDTO data);
    UserReturnDTO updateUserInfo(UserUpdateDTO dto, String tokenJWT);
}
