package com.geekcatalog.api.domain.gameList.DTO;

import com.geekcatalog.api.domain.gameList.GameList;

import java.util.UUID;

public record GameListFullReturnDTO(UUID id, String userId, UUID gameId, String gameName, UUID listId, UUID consoleId, String consoleName, String note, int rating) {
    public GameListFullReturnDTO(GameList gameList, int rating) {
        this(
                gameList.getId(),
                gameList.getUser().getId(),
                gameList.getGame().getId(),
                gameList.getGame().getName(),
                gameList.getList().getId(),
                gameList.getConsole() != null ? gameList.getConsole().getId() : null,
                gameList.getConsole() != null ? gameList.getConsole().getName() : "",
                gameList.getNote() != null ? gameList.getNote() : "",
                rating
        );
    }

    public GameListFullReturnDTO(GameList gameList) {
        this(
                gameList.getId(),
                gameList.getUser().getId(),
                gameList.getGame().getId(),
                gameList.getGame().getName(),
                gameList.getList().getId(),
                gameList.getConsole() != null ? gameList.getConsole().getId() : null,
                gameList.getConsole() != null ? gameList.getConsole().getName() : "",
                gameList.getNote() != null ? gameList.getNote() : "",
                0
        );
    }
}
