package com.geekcatalog.api.service;

import com.geekcatalog.api.dto.user.UserDTO;
import com.geekcatalog.api.dto.user.UserLoginDTO;
import com.geekcatalog.api.dto.user.UserResetPassDTO;
import com.geekcatalog.api.dto.user.UserReturnDTO;
import com.geekcatalog.api.dto.utils.AuthTokensDTO;
import com.geekcatalog.api.dto.utils.MessageResponseDTO;
import jakarta.servlet.http.HttpServletRequest;

public interface AuthService {
    UserReturnDTO getUserByIdClaim(String tokenJWT);
    MessageResponseDTO resetPassword(UserResetPassDTO data);
    AuthTokensDTO signIn(UserLoginDTO data, HttpServletRequest request);
    UserReturnDTO signUp(UserDTO data);
}
