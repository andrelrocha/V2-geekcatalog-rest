package com.geekcatalog.api.domain.imageGame_legacy.DTO;

import com.geekcatalog.api.domain.imageGame_legacy.ImageGameLegacy;

import java.util.UUID;

public record ImageGameReturnLegacyDTO(UUID gameId, byte[] imageFile) {
    public ImageGameReturnLegacyDTO(ImageGameLegacy imageGameLegacy) {
        this(imageGameLegacy.getGame().getId(), imageGameLegacy.getImage());
    }
}
