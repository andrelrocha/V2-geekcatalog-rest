package com.geekcatalog.api.dto.user;

import com.geekcatalog.api.domain.country.Country;
import com.geekcatalog.api.domain.user.User;
import com.geekcatalog.api.domain.user.UserTheme;
import com.geekcatalog.api.domain.userRole.UserRole;
import com.geekcatalog.api.dto.country.CountryReturnDTO;
import com.geekcatalog.api.dto.role.RoleReturnDTO;
import com.geekcatalog.api.dto.userRole.UserRoleReturnDTO;

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
        boolean refreshTokenEnabled,
        boolean twoFactorEnabled,
        UserTheme theme,
        String profilePicUrl,
        List<RoleReturnDTO> roles,
        CountryReturnDTO country
) {
    public UserReturnDTO(User user) {
        this(
                user.getId(),
                user.getEmail(),
                user.getUsername(),
                user.getName(),
                user.getPhone(),
                user.getBirthday(),
                user.isRefreshTokenEnabled(),
                user.isTwoFactorEnabled(),
                user.getTheme() != null ? user.getTheme() : null,
                user.getProfilePicUrl(),
                user.getUserRoles().stream().map(ur -> new RoleReturnDTO(ur.getRole())).toList(),
                user.getCountry() != null ? new CountryReturnDTO(user.getCountry()) : null
        );
    }

    public UserReturnDTO(User user, List<UserRoleReturnDTO> userRoles) {
        this(
                user.getId(),
                user.getEmail(),
                user.getUsername(),
                user.getName(),
                user.getPhone(),
                user.getBirthday(),
                user.isRefreshTokenEnabled(),
                user.isTwoFactorEnabled(),
                user.getTheme() != null ? user.getTheme() : null,
                user.getProfilePicUrl(),
                userRoles.stream().map(UserRoleReturnDTO::role).toList(),
                user.getCountry() != null ? new CountryReturnDTO(user.getCountry()) : null
        );
    }
}
