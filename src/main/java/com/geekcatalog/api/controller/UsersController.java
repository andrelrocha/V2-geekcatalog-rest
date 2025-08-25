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
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
@Tag(name = "User routes mapped on Controller.")
@AllArgsConstructor
public class UsersController {
    private final UserService service;

    @DeleteMapping("/{userId}")
    public ResponseEntity<Void> deleteUser(@PathVariable String userId) {
        service.deleteUser(userId);
        return ResponseEntity.noContent().build();
    }

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

    @GetMapping("/{userId}")
    public ResponseEntity<ApiResponseDTO<UserPublicReturnDTO>> getUserPublicInfo(@PathVariable String userId) {
        var userPublicInfo = service.getPublicInfoByUserId(userId);
        return ResponseEntity.ok(ApiResponseDTO.success(userPublicInfo));
    }

    @GetMapping
    public ResponseEntity<ApiResponseDTO<Page<UserReturnDTO>>> getUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "username") String sortField,
            @RequestParam(defaultValue = "asc") String sortOrder,
            @RequestParam(required = false) String id,
            @RequestParam(required = false) String email,
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String roleId,
            @RequestParam(required = false) String name
    ) {
        String fieldToSort = switch (sortField) {
            case "username" -> "username";
            case "email" -> "email";
            case "name" -> "name";
            case "role" -> "role.name";
            default -> sortField;
        };

        Pageable pageable = PageRequest.of(
                page,
                size,
                Sort.by(Sort.Direction.fromString(sortOrder), fieldToSort)
        );

        var result = service.getUsersPageable(
                pageable,
                id,
                email,
                username,
                roleId,
                name
        );

        return ResponseEntity.ok(ApiResponseDTO.success(result));
    }

}
