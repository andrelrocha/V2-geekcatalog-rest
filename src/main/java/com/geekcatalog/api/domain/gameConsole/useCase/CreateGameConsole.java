package com.geekcatalog.api.domain.gameConsole.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.consoles.ConsoleRepository;
import com.geekcatalog.api.domain.game.GameRepository;
import com.geekcatalog.api.domain.gameConsole.DTO.CreateGameConsoleDTO;
import com.geekcatalog.api.domain.gameConsole.DTO.GameConsoleDTO;
import com.geekcatalog.api.domain.gameConsole.DTO.GameConsoleReturnDTO;
import com.geekcatalog.api.domain.gameConsole.GameConsole;
import com.geekcatalog.api.domain.gameConsole.GameConsoleRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;

import java.util.UUID;

@Component
public class CreateGameConsole {
    @Autowired
    private GameConsoleRepository repository;
    @Autowired
    private GameRepository gameRepository;
    @Autowired
    private ConsoleRepository consoleRepository;

    public GameConsoleReturnDTO createGameConsole(GameConsoleDTO data) {
        var gameIdUUID = UUID.fromString(data.gameId());
        var consoleIdUUID = UUID.fromString(data.consoleId());

        var entityAlreadyCreated = repository.existsByGameIdAndConsoleId(gameIdUUID, consoleIdUUID);

        if (entityAlreadyCreated) {
            throw new ValidationException("A record with the provided game ID and console ID already exists.");
        }

        var game = gameRepository.findById(gameIdUUID)
                .orElseThrow(() -> new ValidationException("No game found with the provided ID when attempting to create a gameconsole."));

        var console = consoleRepository.findById(consoleIdUUID)
                .orElseThrow(() -> new ValidationException("No console found with the provided ID when attempting to create a gameconsole."));

        var createDTO = new CreateGameConsoleDTO(game, console);

        var gameConsole = new GameConsole(createDTO);

        var gameConsoleOnDB = repository.save(gameConsole);

        return new GameConsoleReturnDTO(gameConsoleOnDB);
    }
}