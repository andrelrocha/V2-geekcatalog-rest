package com.geekcatalog.api.controller;

import com.geekcatalog.api.dto.user.*;
import com.geekcatalog.api.dto.utils.ApiResponseDTO;
import com.geekcatalog.api.dto.utils.MessageResponseDTO;
import com.geekcatalog.api.dto.utils.TokenDTO;
import com.geekcatalog.api.infra.utils.httpCookies.CookieManager;
import com.geekcatalog.api.service.AuthService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@Tag(name = "Authentication routes mapped on Controller.")
@AllArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final CookieManager cookieManager;

    @PostMapping("/password/forgot")
    public ResponseEntity<ApiResponseDTO<MessageResponseDTO>> forgotPassword(@RequestBody @Valid UserOnlyEmailDTO data) {
        var messageResponseDTO = authService.forgotPassword(data);
        return ResponseEntity.ok(ApiResponseDTO.success(messageResponseDTO));
    }

    @PostMapping("/password/reset")
    public ResponseEntity<ApiResponseDTO<MessageResponseDTO>> resetPassword(@RequestBody @Valid UserResetPassDTO data) {
        var messageResponseDTO = authService.resetPassword(data);
        return ResponseEntity.ok(ApiResponseDTO.success(messageResponseDTO));
    }

    @PostMapping("/signin")
    public ResponseEntity<ApiResponseDTO<TokenDTO>> performSignin(@RequestBody @Valid UserSignInDTO data,
                                                                  HttpServletResponse response,
                                                                  HttpServletRequest request) {
        var tokensJwt = authService.signIn(data, request);
        cookieManager.addRefreshTokenCookie(response, tokensJwt.refreshToken());
        return ResponseEntity.ok(ApiResponseDTO.success(new TokenDTO(tokensJwt.accessToken())));
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponseDTO<TokenDTO>> updateAccessToken(HttpServletRequest request) {
        var refreshToken = cookieManager.getRefreshTokenFromCookie(request);
        var newAccessToken = authService.refreshAccessToken(refreshToken);
        return ResponseEntity.ok(ApiResponseDTO.success(newAccessToken));
    }


    @PostMapping("/logout")
    public ResponseEntity<ApiResponseDTO<MessageResponseDTO>> logout(HttpServletResponse response, HttpServletRequest request) {
        authService.logout(request, response);
        return ResponseEntity.ok(ApiResponseDTO.success(new MessageResponseDTO("User was successfully logged off.")));
    }
}
