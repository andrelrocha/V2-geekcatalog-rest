package com.geekcatalog.api.dto.user;

import java.time.LocalDate;

public record UserUpdateDTO(String name,
                            String username,
                            Boolean twoFactorEnabled,
                            Boolean refreshTokenEnabled,
                            String phone,
                            LocalDate birthday,
                            String countryId,
                            String theme) {
}
