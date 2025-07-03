package com.geekcatalog.api.service.old.impl;

import com.geekcatalog.api.domain.gameList.DTO.*;
import com.geekcatalog.api.domain.gameList.useCase.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import com.geekcatalog.api.domain.genres.DTO.GenreCountDTO;
import com.geekcatalog.api.service.old.GameListService;

import java.util.ArrayList;

@Service
public class GameListServiceImpl implements GameListService {
    @Autowired
    private AddBulkGameList addBulkGameList;
    @Autowired
    private AddGameList addGameList;
    @Autowired
    private CountGameListByListID countGameListByListID;
    @Autowired
    private DeleteGameList deleteGameList;
    @Autowired
    private GetGameListByListID getGameListByListID;
    @Autowired
    private GetGameListByID getGameListByID;
    @Autowired
    private GetLatestGameListByListID getLatestGameListByListID;
    @Autowired
    private GetGameIdAndConsolesAvailableByGameListID getGameIdAndConsolesAvailableByGameListID;
    @Autowired
    private GetAllGameListGenresByUser getAllGameListGenresByUser;
    @Autowired
    private UpdateGameList updateGameList;

    @Override
    public Page<GameListUriReturnDTO> getGamesByListID(Pageable pageable, String listId) {
        return getGameListByListID.getGamesByListID(pageable, listId);
    }

    @Override
    public GameListFullReturnDTO getGameListByID(String gameListID) {
        return getGameListByID.getGameListByID(gameListID);
    }

    @Override
    public Page<GameListReturnDTO> getLatestGamesByListID(Pageable pageable, String listId) {
        return getLatestGameListByListID.getLatestGamesByListID(pageable, listId);
    }

    @Override
    public GameListGameAndConsolesDTO getGameInfoByGameListID(String gameListId) {
        return getGameIdAndConsolesAvailableByGameListID.getGameInfoByGameListID(gameListId);
    }

    @Override
    public Page<GenreCountDTO> getAllGameListGenresByUserId(String tokenJWT, Pageable pageable) {
        return getAllGameListGenresByUser.getAllGameListGenresByUserId(tokenJWT, pageable);
    }

    @Override
    public CountGameListReturnDTO countGamesByListID(String listId) {
        return countGameListByListID.countGamesByListID(listId);
    }

    @Override
    public ArrayList<GameListBulkReturnDTO> addBulkGamesToList(GameListBulkCreateDTO data) {
        return addBulkGameList.addBulkGamesToList(data);
    }

    @Override
    public GameListFullReturnDTO addGameList(GameListDTO data) {
        return addGameList.addGameList(data);
    }

    @Override
    public GameListFullReturnDTO updateGameList(GameListUpdateRequestDTO data, String gameListId) {
        return updateGameList.updateGameList(data, gameListId);
    }

    @Override
    public void deleteGameList(DeleteGameListDTO data) {
        deleteGameList.deleteGameList(data);
    }
}
