package com.geekcatalog.api.dto.user;

import com.geekcatalog.api.domain.user.User;
import com.geekcatalog.api.domain.userRole.UserRole;

import java.time.LocalDate;
import java.util.List;
import java.util.stream.Collectors;

public record UserReturnDTO(
        String id,
        String email,
        String username,
        String name,
        String phone,
        LocalDate birthday,
        String country,
        boolean refreshTokenEnabled,
        boolean twoFactorEnabled,
        String theme,
        String profilePicUrl,
        List<String> rolesIds,
        List<String> rolesNames
) {
    public UserReturnDTO(User user) {
        this(
                user.getId(),
                user.getEmail(),
                user.getUsername(),
                user.getName(),
                user.getPhone(),
                user.getBirthday(),
                user.getCountry() != null ? user.getCountry().getNameCommon() : null,
                user.isRefreshTokenEnabled(),
                user.isTwoFactorEnabled(),
                user.getTheme() != null ? user.getTheme().name() : null,
                user.getProfilePicUrl(),
                user.getUserRoles().stream().map(ur -> ur.getRole().getId()).toList(),
                user.getUserRoles().stream().map(ur -> ur.getRole().getName()).toList()
        );
    }

    public UserReturnDTO(User user, List<UserRole> roles) {
        this(
                user.getId(),
                user.getEmail(),
                user.getUsername(),
                user.getName(),
                user.getPhone(),
                user.getBirthday(),
                user.getCountry() != null ? user.getCountry().getNameCommon() : null,
                user.isRefreshTokenEnabled(),
                user.isTwoFactorEnabled(),
                user.getTheme() != null ? user.getTheme().name() : null,
                user.getProfilePicUrl(),
                roles.stream().map(ur -> ur.getRole().getId()).collect(Collectors.toList()),
                roles.stream().map(ur -> ur.getRole().getName()).collect(Collectors.toList())
        );
    }
}
