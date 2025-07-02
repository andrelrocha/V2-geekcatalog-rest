package com.geekcatalog.api.domain.gameStudio.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.game.GameRepository;
import com.geekcatalog.api.domain.gameStudio.DTO.CreateGameStudioDTO;
import com.geekcatalog.api.domain.gameStudio.DTO.GameStudioDTO;
import com.geekcatalog.api.domain.gameStudio.DTO.GameStudioReturnDTO;
import com.geekcatalog.api.domain.gameStudio.GameStudio;
import com.geekcatalog.api.domain.gameStudio.GameStudioRepository;
import com.geekcatalog.api.domain.studios.StudioRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;

import java.util.UUID;

@Component
public class CreateGameStudio {
    @Autowired
    private GameStudioRepository repository;

    @Autowired
    private GameRepository gameRepository;

    @Autowired
    private StudioRepository studioRepository;

    public GameStudioReturnDTO createGameStudio(GameStudioDTO data) {
        var gameIdUUID = UUID.fromString(data.gameId());
        var studioIdUUID = UUID.fromString(data.studioId());

        var entityAlreadyCreated = repository.existsByGameIdAndStudioId(gameIdUUID, studioIdUUID);

        if (entityAlreadyCreated) {
            throw new ValidationException("A record with the provided game ID and studio ID already exists");
        }

        var game = gameRepository.findById(gameIdUUID)
                .orElseThrow(() -> new ValidationException("No game found with the provided ID when attempting to create GameStudio"));

        var studio = studioRepository.findById(studioIdUUID)
                .orElseThrow(() -> new ValidationException("No studio found with the provided ID when attempting to create GameStudio"));

        var createDTO = new CreateGameStudioDTO(game, studio);

        var gameStudio = new GameStudio(createDTO);

        var gameStudioOnDB = repository.save(gameStudio);

        return new GameStudioReturnDTO(gameStudioOnDB);
    }

}
