package com.geekcatalog.api.domain.gameConsole.DTO;

import com.geekcatalog.api.domain.gameConsole.GameConsole;

import java.util.UUID;

public record GameConsoleReturnDTO(UUID id, String gameName, UUID consoleId, String consoleName) {
    public GameConsoleReturnDTO(GameConsole gameConsole) {
        this(gameConsole.getId(), gameConsole.getGame().getName(), gameConsole.getConsole().getId(), gameConsole.getConsole().getName());
    }
}
