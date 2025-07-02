package com.geekcatalog.api.domain.studios.DTO;

import com.geekcatalog.api.domain.studios.Studio;

import java.util.UUID;

public record StudioReturnDTO(UUID id, String name, String countryName, UUID countryId) {

    public StudioReturnDTO(Studio studio) {
        this(studio.getId(), studio.getName(), studio.getCountry().getName(), studio.getCountry().getId());
    }
}
