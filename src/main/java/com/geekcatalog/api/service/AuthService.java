package com.geekcatalog.api.service;

import com.geekcatalog.api.dto.user.*;
import com.geekcatalog.api.dto.utils.AuthTokensDTO;
import com.geekcatalog.api.dto.utils.MessageResponseDTO;
import jakarta.servlet.http.HttpServletRequest;

public interface AuthService {
    MessageResponseDTO forgotPassword(UserOnlyEmailDTO data);
    UserReturnDTO getUserByIdClaim(String tokenJWT);
    MessageResponseDTO resetPassword(UserResetPassDTO data);
    AuthTokensDTO signIn(UserLoginDTO data, HttpServletRequest request);
    UserReturnDTO signUp(UserDTO data);
}
