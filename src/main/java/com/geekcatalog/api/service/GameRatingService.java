package com.geekcatalog.api.service;

import com.geekcatalog.api.domain.gameRating.DTO.*;

public interface GameRatingService {
    GameRatingReturnDTO addGameRating(GameRatingDTO data);
    AllRatingsGameDTO getAllRatingsByGameID(String gameId);
    GameRatingReturnDTO getRatingByGameAndUser(GameRatingByGameAndJWTDTO data);
    GameRatingAverageDTO getAverageRatingByJWT(String tokenJWT);
}
