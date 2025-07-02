package com.geekcatalog.api.domain.gameRating.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.gameRating.DTO.GameRatingByGameAndUserDTO;
import com.geekcatalog.api.domain.gameRating.DTO.GameRatingReturnDTO;
import com.geekcatalog.api.domain.gameRating.GameRatingRepository;

import java.util.UUID;

@Component
public class GetRatingByGameAndUserID {
    @Autowired
    private GameRatingRepository gameRatingRepository;

    public GameRatingReturnDTO getRatingByGameAndUser(GameRatingByGameAndUserDTO data) {
        var gameIdUUID = UUID.fromString(data.gameId());
        var userIdUUID = UUID.fromString(data.userId());

        var gameRating = gameRatingRepository.findByGameIdAndUserId(gameIdUUID, userIdUUID);

        if (gameRating == null) {
            return new GameRatingReturnDTO(gameIdUUID, userIdUUID, "", 0);
        }

        return new GameRatingReturnDTO(gameRating);
    }
}
