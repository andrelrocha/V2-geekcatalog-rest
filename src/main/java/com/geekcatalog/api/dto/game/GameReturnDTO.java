package com.geekcatalog.api.dto.game;

import com.geekcatalog.api.domain.game.Game;

public record GameReturnDTO(String id, String name, String description, Integer releaseYear) {
    public GameReturnDTO(Game game) {
        this(game.getId(), game.getName(), game.getDescription(), game.getReleaseYear());
    }
}
