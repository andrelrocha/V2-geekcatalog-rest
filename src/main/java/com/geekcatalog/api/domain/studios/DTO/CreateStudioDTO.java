package com.geekcatalog.api.domain.studios.DTO;

import com.geekcatalog.api.domain.country.Country;

public record CreateStudioDTO(String name, Country country) {
}
