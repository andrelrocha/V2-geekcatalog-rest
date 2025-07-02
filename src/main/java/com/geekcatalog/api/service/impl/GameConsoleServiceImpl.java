package com.geekcatalog.api.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import com.geekcatalog.api.domain.gameConsole.DTO.GameConsoleDTO;
import com.geekcatalog.api.domain.gameConsole.DTO.GameConsoleReturnDTO;
import com.geekcatalog.api.domain.gameConsole.DTO.UpdateGameConsoleDTO;
import com.geekcatalog.api.domain.gameConsole.useCase.CreateGameConsole;
import com.geekcatalog.api.domain.gameConsole.useCase.GetAllGameConsolesByGameID;
import com.geekcatalog.api.domain.gameConsole.useCase.UpdateGameConsoles;
import com.geekcatalog.api.service.GameConsoleService;

@Service
public class GameConsoleServiceImpl implements GameConsoleService {
    @Autowired
    private CreateGameConsole createGameConsole;
    @Autowired
    private GetAllGameConsolesByGameID getAllGameConsolesByGameID;
    @Autowired
    private UpdateGameConsoles updateGameConsoles;

    @Override
    public Page<GameConsoleReturnDTO> getAllGameConsolesByGameId(String gameId, Pageable pageable) {
        var gameConsoles = getAllGameConsolesByGameID.getAllGameConsolesByGameId(gameId, pageable);
        return gameConsoles;
    }

    @Override
    public GameConsoleReturnDTO createGameConsole(GameConsoleDTO data) {
        var newGameConsole = createGameConsole.createGameConsole(data);
        return newGameConsole;
    }

    @Override
    public Page<GameConsoleReturnDTO> updateGameConsoles(UpdateGameConsoleDTO data, String gameId) {
        var updatedGameConsoles = updateGameConsoles.updateGameConsoles(data, gameId);
        return updatedGameConsoles;
    }
}
