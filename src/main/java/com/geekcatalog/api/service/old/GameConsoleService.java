package com.geekcatalog.api.service.old;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import com.geekcatalog.api.domain.gameConsole.DTO.GameConsoleDTO;
import com.geekcatalog.api.domain.gameConsole.DTO.GameConsoleReturnDTO;
import com.geekcatalog.api.domain.gameConsole.DTO.UpdateGameConsoleDTO;

public interface GameConsoleService {
    Page<GameConsoleReturnDTO> getAllGameConsolesByGameId(String gameId, Pageable pageable);
    GameConsoleReturnDTO createGameConsole(GameConsoleDTO data);
    Page<GameConsoleReturnDTO> updateGameConsoles(UpdateGameConsoleDTO data, String gameId);
}
