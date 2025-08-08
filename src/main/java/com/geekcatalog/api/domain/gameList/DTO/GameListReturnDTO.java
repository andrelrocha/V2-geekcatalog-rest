package com.geekcatalog.api.domain.gameList.DTO;

import com.geekcatalog.api.domain.gameList.GameList;

import java.util.UUID;

public record GameListReturnDTO(UUID id, String userId, UUID gameId, String gameName, UUID listId, UUID consoleId) {
    public GameListReturnDTO(GameList gameList) {
        this(gameList.getId(), gameList.getUser().getId(), gameList.getGame().getId(), gameList.getGame().getName(), gameList.getList().getId(), gameList.getConsole() != null ? gameList.getConsole().getId() : null);
    }
}
