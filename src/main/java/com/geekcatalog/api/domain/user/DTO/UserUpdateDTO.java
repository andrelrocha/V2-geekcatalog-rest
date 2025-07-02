package com.geekcatalog.api.domain.user.DTO;

import com.geekcatalog.api.domain.country.Country;
import com.geekcatalog.api.domain.user.User;

import java.time.LocalDate;

public record UserUpdateDTO(String name,
                            String username,
                            Boolean twoFactorEnabled,
                            Boolean refreshTokenEnabled,
                            String phone,
                            LocalDate birthday,
                            Country country,
                            String theme) {

    public UserUpdateDTO(User user, LocalDate birthday, Country country) {
        this(user.getName(), user.getUsername(), user.isTwoFactorEnabled(), user.isRefreshTokenEnabled(), user.getPhone(), birthday, country, user.getTheme().toString());
    }
}
