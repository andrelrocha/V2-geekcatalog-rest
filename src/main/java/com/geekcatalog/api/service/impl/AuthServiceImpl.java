package com.geekcatalog.api.service.impl;

import com.geekcatalog.api.domain.user.UseCase.CreateUser;
import com.geekcatalog.api.domain.user.UseCase.PerformLogin;
import com.geekcatalog.api.dto.user.UserDTO;
import com.geekcatalog.api.dto.user.UserLoginDTO;
import com.geekcatalog.api.dto.user.UserReturnDTO;
import com.geekcatalog.api.dto.utils.AuthTokensDTO;
import com.geekcatalog.api.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AuthServiceImpl implements AuthService {
    @Autowired
    private CreateUser createUser;
    @Autowired
    private PerformLogin performLogin;

    @Override
    public AuthTokensDTO signIn(UserLoginDTO data, HttpServletRequest request) {
        return performLogin.performLogin(data, request);
    }

    @Override
    public UserReturnDTO signUp(UserDTO data) {
        return createUser.signUp(data);
    }
}
