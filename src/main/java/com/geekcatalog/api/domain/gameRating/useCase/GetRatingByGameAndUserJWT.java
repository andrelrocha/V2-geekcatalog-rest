package com.geekcatalog.api.domain.gameRating.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.gameRating.DTO.GameRatingByGameAndJWTDTO;
import com.geekcatalog.api.domain.gameRating.DTO.GameRatingReturnDTO;
import com.geekcatalog.api.domain.gameRating.GameRatingRepository;
import com.geekcatalog.api.domain.user.UseCase.GetUserByTokenJWT;

import java.util.UUID;

@Component
public class GetRatingByGameAndUserJWT {
    @Autowired
    private GameRatingRepository gameRatingRepository;
    @Autowired
    private GetUserByTokenJWT getUserByTokenJWT;

    public GameRatingReturnDTO getRatingByGameAndUser(GameRatingByGameAndJWTDTO data) {
        var gameIdUUID = UUID.fromString(data.gameId());

        var user = getUserByTokenJWT.getUserByID(data.tokenJWT());

        var gameRating = gameRatingRepository.findByGameIdAndUserId(gameIdUUID, user.id());

        if (gameRating == null) {
            return new GameRatingReturnDTO(gameIdUUID, user.id(), user.name(), 0);
        }

        return new GameRatingReturnDTO(gameRating);
    }
}
