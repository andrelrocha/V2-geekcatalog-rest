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
    /*
    @DeleteMapping("/user/{id}")
    @Transactional
    public ResponseEntity<Void> deleteUser(@PathVariable String id) {
        authService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }



    @GetMapping("/user/me")
    public ResponseEntity<ApiResponseDTO<UserReturnDTO>> getUserByTokenJWT(@RequestHeader("Authorization") String authorizationHeader) {
        var tokenJWT = authorizationHeader.replaceFirst("(?i)^Bearer\\s+", "").trim();
        var user = authService.getUserByIdClaim(tokenJWT);
        return ResponseEntity.ok(ApiResponseDTO.success(user));
    }

    @GetMapping("/user/public/{userId}")
    public ResponseEntity<ApiResponseDTO<UserPublicReturnDTO>> getUserPublicInfo(@PathVariable String userId) {
        var user = authService.getPublicInfoByUserId(userId);
        return ResponseEntity.ok(ApiResponseDTO.success(user));
    }



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
    */


}
