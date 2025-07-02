package com.geekcatalog.api.domain.gameConsole.DTO;

import com.geekcatalog.api.domain.consoles.Console;
import com.geekcatalog.api.domain.game.Game;

public record CreateGameConsoleDTO(Game game, Console console) {
}
