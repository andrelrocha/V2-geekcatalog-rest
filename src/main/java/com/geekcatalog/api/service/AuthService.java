package com.geekcatalog.api.service;

import com.geekcatalog.api.dto.user.UserLoginDTO;
import com.geekcatalog.api.dto.utils.AuthTokensDTO;
import jakarta.servlet.http.HttpServletRequest;

public interface AuthService {
    AuthTokensDTO signIn(UserLoginDTO data, HttpServletRequest request);
}
