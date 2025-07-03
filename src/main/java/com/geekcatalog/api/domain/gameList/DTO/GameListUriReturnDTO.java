package com.geekcatalog.api.domain.gameList.DTO;

import com.geekcatalog.api.domain.gameList.GameList;

import java.util.UUID;

public record GameListUriReturnDTO(UUID id, String userId, UUID gameId, String gameName, UUID consoleId, String consolePlayed, String uri) {
    public GameListUriReturnDTO(GameList gameList, String uri) {
        this(gameList.getId(), gameList.getUser().getId(), gameList.getGame().getId(), gameList.getGame().getName(),
                gameList.getConsole() != null ? gameList.getConsole().getId() : null,  gameList.getConsole() != null ? gameList.getConsole().getName() : null, uri);
    }
}
