package com.geekcatalog.api.controller;

import com.geekcatalog.api.dto.user.UserDTO;
import com.geekcatalog.api.dto.user.UserLoginDTO;
import com.geekcatalog.api.dto.user.UserReturnDTO;
import com.geekcatalog.api.dto.utils.AccessTokenDTO;
import com.geekcatalog.api.dto.utils.ApiResponseDTO;
import com.geekcatalog.api.infra.utils.httpCookies.CookieManager;
import com.geekcatalog.api.service.AuthService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@Tag(name = "Authentication routes mapped on Controller.")
public class AuthController {
    @Autowired
    private AuthService authService;

    @Autowired
    private CookieManager cookieManager;

    @PostMapping("/signin")
    @Transactional
    public ResponseEntity<ApiResponseDTO<AccessTokenDTO>> signIn(@RequestBody @Valid UserLoginDTO data,
                                                                        HttpServletResponse response,
                                                                        HttpServletRequest request) {
        var tokensJwt = authService.signIn(data, request);
        if (tokensJwt.refreshToken() != null) {
            cookieManager.addRefreshTokenCookie(response, tokensJwt.refreshToken());
        }
        return ResponseEntity.ok(ApiResponseDTO.success(new AccessTokenDTO(tokensJwt.accessToken())));
    }

    @PostMapping("/signup")
    @Transactional
    public ResponseEntity<ApiResponseDTO<UserReturnDTO>> signUp(@RequestBody @Valid UserDTO data) {
        var newUserDTO = authService.signUp(data);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponseDTO.success(newUserDTO));
    }
}
