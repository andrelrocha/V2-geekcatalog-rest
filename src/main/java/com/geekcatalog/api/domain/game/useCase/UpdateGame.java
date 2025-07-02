package com.geekcatalog.api.domain.game.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.game.DTO.GameDTO;
import com.geekcatalog.api.domain.game.DTO.GameReturnDTO;
import com.geekcatalog.api.domain.game.GameRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;

import java.util.UUID;

@Component
public class UpdateGame {
    @Autowired
    private GameRepository repository;

    public GameReturnDTO updateGame(GameDTO data, String gameId) {
        var gameIdUUID = UUID.fromString(gameId);

        var game = repository.findById(gameIdUUID)
                .orElseThrow(() -> new ValidationException("No game was found for the provided ID."));

        game.updateGame(data);

        var gameOnDB = repository.save(game);

        return new GameReturnDTO(gameOnDB);
    }
}
