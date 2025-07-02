package com.geekcatalog.api.domain.studios.DTO;

import com.geekcatalog.api.domain.studios.Studio;

import java.util.UUID;

public record StudioReturnFullGameInfo(UUID id, String name) {
    public StudioReturnFullGameInfo(Studio studio) {
        this(studio.getId(), studio.getName());
    }
}
