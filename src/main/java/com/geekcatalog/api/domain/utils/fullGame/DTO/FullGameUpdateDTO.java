package com.geekcatalog.api.domain.utils.fullGame.DTO;

import com.geekcatalog.api.domain.game.Game;

import java.util.ArrayList;

public record FullGameUpdateDTO(String name, Integer metacritic, Integer yearOfRelease, ArrayList<String> consoles, ArrayList<String> genres, ArrayList<String> studios) {
    public FullGameUpdateDTO(Game game, ArrayList<String> consoles, ArrayList<String> genres, ArrayList<String> studios) {
        this(game.getName(), game.getMetacritic(), game.getYearOfRelease(), consoles, genres, studios);
    }
}
