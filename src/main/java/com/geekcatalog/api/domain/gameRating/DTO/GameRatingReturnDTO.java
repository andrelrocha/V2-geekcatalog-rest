package com.geekcatalog.api.domain.gameRating.DTO;

import com.geekcatalog.api.domain.gameRating.GameRating;

import java.util.UUID;

public record GameRatingReturnDTO(UUID gameId, String userId, String userName, int rating) {
    public GameRatingReturnDTO(GameRating gameRating) {
        this(gameRating.getGame().getId(), gameRating.getUser().getId(), gameRating.getUser().getName(), gameRating.getRating());
    }
}
