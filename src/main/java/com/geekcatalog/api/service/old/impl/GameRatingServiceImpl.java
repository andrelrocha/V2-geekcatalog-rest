package com.geekcatalog.api.service.old.impl;

import com.geekcatalog.api.domain.gameRating.DTO.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.geekcatalog.api.domain.gameRating.useCase.AddGameRating;
import com.geekcatalog.api.domain.gameRating.useCase.GetAverageRatingByUserJWT;
import com.geekcatalog.api.domain.gameRating.useCase.GetRatingByGameAndUserJWT;
import com.geekcatalog.api.domain.gameRating.useCase.GetRatingByGameId;
import com.geekcatalog.api.service.old.GameRatingService;

@Service
public class GameRatingServiceImpl implements GameRatingService {
    @Autowired
    private AddGameRating addGameRating;
    @Autowired
    private GetRatingByGameId getRatingByGameId;
    @Autowired
    private GetRatingByGameAndUserJWT getRatingByGameAndUserJWT;
    @Autowired
    private GetAverageRatingByUserJWT getAverageRatingByUserJWT;

    @Override
    public GameRatingReturnDTO addGameRating(GameRatingDTO data) {
        return addGameRating.addGameRating(data);
    }

    @Override
    public AllRatingsGameDTO getAllRatingsByGameID(String gameId) {
        return getRatingByGameId.getAllRatingsByGameID(gameId);
    }

    @Override
    public GameRatingReturnDTO getRatingByGameAndUser(GameRatingByGameAndJWTDTO data) {
        return getRatingByGameAndUserJWT.getRatingByGameAndUser(data);
    }

    @Override
    public GameRatingAverageDTO getAverageRatingByJWT(String tokenJWT) {
        return getAverageRatingByUserJWT.getAverageRatingByJWT(tokenJWT);
    }
}
