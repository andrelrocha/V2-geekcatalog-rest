package com.geekcatalog.api.domain.gameList.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.gameList.DTO.CountGameListReturnDTO;
import com.geekcatalog.api.domain.gameList.GameListRepository;

import java.util.UUID;

@Component
public class CountGameListByListID {
    @Autowired
    private GameListRepository gameListRepository;

    public CountGameListReturnDTO countGamesByListID(String listId) {
        var listIdUUID = UUID.fromString(listId);

        var gameListCount = gameListRepository.countGameListsByListId(listIdUUID);

        return new CountGameListReturnDTO(gameListCount);
    }
}
