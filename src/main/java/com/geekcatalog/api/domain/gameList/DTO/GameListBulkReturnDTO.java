package com.geekcatalog.api.domain.gameList.DTO;

import com.geekcatalog.api.domain.gameList.GameList;

import java.util.UUID;

public record GameListBulkReturnDTO(UUID id, String userId, UUID gameId, String gameName, UUID listId) {
    public GameListBulkReturnDTO(GameList gameList) {
        this(gameList.getId(), gameList.getUser().getId(), gameList.getGame().getId(), gameList.getGame().getName(), gameList.getList().getId());
    }
}
