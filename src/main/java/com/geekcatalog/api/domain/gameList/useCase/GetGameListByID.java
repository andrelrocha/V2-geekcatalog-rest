package com.geekcatalog.api.domain.gameList.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.gameList.DTO.GameListFullReturnDTO;
import com.geekcatalog.api.domain.gameList.GameListRepository;
import com.geekcatalog.api.domain.gameRating.DTO.GameRatingByGameAndUserDTO;
import com.geekcatalog.api.domain.gameRating.useCase.GetRatingByGameAndUserID;
import com.geekcatalog.api.infra.exceptions.ValidationException;

import java.util.UUID;

@Component
public class GetGameListByID {
    @Autowired
    private GameListRepository repository;
    @Autowired
    private GetRatingByGameAndUserID getRatingByGameAndUserID;

    public GameListFullReturnDTO getGameListByID(String gameListId) {
        var gameListIdUUID = UUID.fromString(gameListId);

        var gameList = repository.findById(gameListIdUUID)
                .orElseThrow(() -> new ValidationException("No game was found in a list with the provided id."));

        var gameRatingDTO = new GameRatingByGameAndUserDTO((gameList.getGame().getId()).toString(), (gameList.getUser().getId()).toString());
        var userRating = getRatingByGameAndUserID.getRatingByGameAndUser(gameRatingDTO);

        return new GameListFullReturnDTO(gameList, userRating.rating());
    }
}
