package com.geekcatalog.api.controller;

import com.geekcatalog.api.dto.user.*;
import com.geekcatalog.api.dto.utils.AccessTokenDTO;
import com.geekcatalog.api.dto.utils.ApiResponseDTO;
import com.geekcatalog.api.infra.utils.httpCookies.CookieManager;
import com.geekcatalog.api.service.AuthService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@Tag(name = "Authentication routes mapped on Controller.")
@AllArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final CookieManager cookieManager;

    @DeleteMapping("/user/me")
    public ResponseEntity deleteUser(@RequestHeader("Authorization") String authorizationHeader) {
        var tokenJWT = authorizationHeader.replaceFirst("(?i)^Bearer\\s+", "").trim();
        authService.deleteUser(tokenJWT);
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/user/me")
    public ResponseEntity<ApiResponseDTO<UserReturnDTO>> updateUser(@RequestHeader("Authorization") String authorizationHeader, @RequestBody UserUpdateDTO data) {
        var tokenJWT = authorizationHeader.replaceFirst("(?i)^Bearer\\s+", "").trim();
        var updatedUser = authService.updateUserInfo(data, tokenJWT);
        return ResponseEntity.ok(ApiResponseDTO.success(updatedUser));
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

    @PostMapping("/password/forgot")
    @Transactional
    public ResponseEntity<ApiResponseDTO<String>> forgotPassword(@RequestBody @Valid UserOnlyEmailDTO data) {
        var messageResponseDTO = authService.forgotPassword(data);
        return ResponseEntity.ok(ApiResponseDTO.success(messageResponseDTO.message()));
    }

    @PostMapping("/password/reset")
    @Transactional
    public ResponseEntity<ApiResponseDTO<String>> resetPassword(@RequestBody @Valid UserResetPassDTO data) {
        var messageResponseDTO = authService.resetPassword(data);
        return ResponseEntity.ok(ApiResponseDTO.success(messageResponseDTO.message()));
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

    @PostMapping("/signup")
    @Transactional
    public ResponseEntity<ApiResponseDTO<UserReturnDTO>> signUp(@RequestBody @Valid UserDTO data) {
        var newUserDTO = authService.signUp(data);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponseDTO.success(newUserDTO));
    }

}
