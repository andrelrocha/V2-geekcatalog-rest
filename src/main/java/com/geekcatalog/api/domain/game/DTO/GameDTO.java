package com.geekcatalog.api.domain.game.DTO;

import com.geekcatalog.api.domain.game.Game;

public record GameDTO(String name, int metacritic, int yearOfRelease) {
    public GameDTO(Game game) {
        this(game.getName(), game.getMetacritic(), game.getYearOfRelease());
    }
}
