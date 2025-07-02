package com.geekcatalog.api.domain.gameGenre.DTO;

import com.geekcatalog.api.domain.game.Game;
import com.geekcatalog.api.domain.genres.Genre;

public record CreateGameGenreDTO(Game game, Genre genre) {
}
