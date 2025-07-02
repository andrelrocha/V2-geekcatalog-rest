package com.geekcatalog.api.domain.user.DTO;

import com.geekcatalog.api.domain.country.Country;

public record UserCreateDTO(UserDTO data, Country country) {
}
