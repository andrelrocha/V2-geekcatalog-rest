package com.geekcatalog.api.domain.game.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.game.DTO.GameDTO;
import com.geekcatalog.api.domain.game.DTO.GameReturnDTO;
import com.geekcatalog.api.domain.game.Game;
import com.geekcatalog.api.domain.game.GameRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;

@Component
public class CreateGame {
    @Autowired
    private GameRepository repository;

    public GameReturnDTO createGame(GameDTO data) {
        var existsByName = repository.existsByName(data.name());

        if (existsByName) {
            throw new ValidationException("There's already a game with the provided name.");
        }

        var game = new Game(data);

        var gameOnDB = repository.save(game);

        return new GameReturnDTO(gameOnDB);
    }
}
