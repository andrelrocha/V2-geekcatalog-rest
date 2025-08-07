package com.geekcatalog.api.controller;

import com.geekcatalog.api.dto.user.UserDTO;
import com.geekcatalog.api.dto.user.UserReturnDTO;
import com.geekcatalog.api.dto.utils.ApiResponseDTO;
import com.geekcatalog.api.service.UserService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
}
