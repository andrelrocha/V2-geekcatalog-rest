package com.geekcatalog.api.domain.gameStudio.DTO;

import com.geekcatalog.api.domain.game.Game;
import com.geekcatalog.api.domain.studios.Studio;

public record CreateGameStudioDTO(Game game, Studio studio) {
}
