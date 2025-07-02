package com.geekcatalog.api.controller;

import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.geekcatalog.api.domain.permission.useCase.GetAllPermissions;

@RestController
@RequestMapping("/permissions")
@Tag(name = "Permission Routes Mapped on Controller")
public class PermissionController {
    @Autowired
    private GetAllPermissions getAllPermissions;

    @GetMapping("/all")
    public ResponseEntity getAllPermissionsPageable (@RequestParam(defaultValue = "0") int page,
                                                   @RequestParam(defaultValue = "20") int size,
                                                   @RequestParam(defaultValue = "permission") String sortField,
                                                   @RequestParam(defaultValue = "asc") String sortOrder) {
        var pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.fromString(sortOrder), sortField));
        var permissionsPageable = getAllPermissions.getAllPermissions(pageable);
        return ResponseEntity.ok(permissionsPageable);
    }
}
