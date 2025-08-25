package com.geekcatalog.api.controller;

import com.geekcatalog.api.dto.user.UserOnlyEmailDTO;
import com.geekcatalog.api.dto.user.UserResetPassDTO;
import com.geekcatalog.api.dto.user.UserSignInDTO;
import com.geekcatalog.api.dto.utils.AuthTokensDTO;
import com.geekcatalog.api.dto.utils.MessageResponseDTO;
import com.geekcatalog.api.dto.utils.TokenDTO;
import com.geekcatalog.api.dto.utils.ApiResponseDTO;
import com.geekcatalog.api.infra.utils.httpCookies.CookieManager;
import com.geekcatalog.api.service.AuthService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@Tag(name = "Authentication routes mapped on controller")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final CookieManager cookieManager;

    @PostMapping("/signin")
    public ResponseEntity<ApiResponseDTO<TokenDTO>> login(
            @RequestBody @Valid UserSignInDTO data,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        AuthTokensDTO tokens = authService.signIn(data, request);
        cookieManager.addRefreshTokenCookie(response, tokens.refreshToken());
        return ResponseEntity.ok(ApiResponseDTO.success(new TokenDTO(tokens.accessToken())));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponseDTO<String>> logout(HttpServletRequest request, HttpServletResponse response) {
        authService.signOut(request, response);
        return ResponseEntity.ok(ApiResponseDTO.success("Logout successful."));
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponseDTO<TokenDTO>> refreshToken(HttpServletRequest request) {
        String refreshToken = cookieManager.getRefreshTokenFromCookie(request);
        TokenDTO newAccessToken = authService.updateToken(refreshToken);
        return ResponseEntity.ok(ApiResponseDTO.success(newAccessToken));
    }

    @PostMapping("/password/forgot")
    public ResponseEntity<ApiResponseDTO<String>> forgotPassword(@RequestBody @Valid UserOnlyEmailDTO data) {
        MessageResponseDTO responseDTO = authService.forgotPassword(data);
        return ResponseEntity.ok(ApiResponseDTO.success(responseDTO.message()));
    }

    @PostMapping("/password/reset")
    public ResponseEntity<ApiResponseDTO<String>> resetPassword(@RequestBody @Valid UserResetPassDTO data) {
        MessageResponseDTO responseDTO = authService.resetPassword(data);
        return ResponseEntity.ok(ApiResponseDTO.success(responseDTO.message()));
    }
}
