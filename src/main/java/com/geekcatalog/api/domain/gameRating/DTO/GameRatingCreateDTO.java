package com.geekcatalog.api.domain.gameRating.DTO;

import com.geekcatalog.api.domain.game.Game;
import com.geekcatalog.api.domain.user.User;

public record GameRatingCreateDTO(Game game, User user, int rating) {
}
