package com.geekcatalog.api.controller;

import com.geekcatalog.api.dto.user.UserDTO;
import com.geekcatalog.api.dto.user.UserPublicReturnDTO;
import com.geekcatalog.api.dto.user.UserReturnDTO;
import com.geekcatalog.api.dto.user.UserUpdateDTO;
import com.geekcatalog.api.dto.utils.ApiResponseDTO;
import com.geekcatalog.api.service.UserService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
@Tag(name = "User routes mapped on Controller.")
@AllArgsConstructor
public class UsersController {
    private final UserService service;

    @PostMapping
    public ResponseEntity<ApiResponseDTO<UserReturnDTO>> create(@RequestBody @Valid UserDTO data) {
        var newUserDTO = service.create(data);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponseDTO.success(newUserDTO));
    }

    @PutMapping("/{userId}")
    public ResponseEntity<ApiResponseDTO<UserReturnDTO>> updateUser(@PathVariable String userId, @RequestBody UserUpdateDTO data) {
        var updatedUser = service.updateUserInfo(data, userId);
        return ResponseEntity.ok(ApiResponseDTO.success(updatedUser));
    }

    @GetMapping("/me")
    public ResponseEntity<ApiResponseDTO<UserReturnDTO>> getUserByJWT(@RequestHeader("Authorization") String authorizationHeader) {
        var tokenJWT = authorizationHeader.replaceFirst("(?i)^Bearer\\s+", "").trim();
        var user = service.getUserByJWT(tokenJWT);
        return ResponseEntity.ok(ApiResponseDTO.success(user));
    }

    @GetMapping("/{userId}")
    public ResponseEntity<ApiResponseDTO<UserPublicReturnDTO>> getUserPublicInfo(@PathVariable String userId) {
        var userPublicInfo = service.getPublicInfoByUserId(userId);
        return ResponseEntity.ok(ApiResponseDTO.success(userPublicInfo));
    }

    @DeleteMapping("/{userId}")
    public ResponseEntity<Void> deleteUser(@PathVariable String userId) {
        service.deleteUser(userId);
        return ResponseEntity.noContent().build();
    }
}
