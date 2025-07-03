package com.geekcatalog.api.domain.listsApp.DTO;

import java.util.ArrayList;
import java.util.UUID;

public record ListAppReturnWithGameIdsDTO(UUID id, String name, String description, String ownerId, String userName, ArrayList<UUID> latestGamesOnListID) {
    public ListAppReturnWithGameIdsDTO(ListAppReturnDTO listAppReturnDTO, ArrayList<UUID> gamesOnListID) {
        this(listAppReturnDTO.id(), listAppReturnDTO.name(), listAppReturnDTO.description(), listAppReturnDTO.ownerId(), listAppReturnDTO.userName(), gamesOnListID);
    }
}
