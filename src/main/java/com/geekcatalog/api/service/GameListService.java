package com.geekcatalog.api.service;

import com.geekcatalog.api.domain.gameList.DTO.*;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import com.geekcatalog.api.domain.genres.DTO.GenreCountDTO;

import java.util.ArrayList;

public interface GameListService {
    Page<GameListUriReturnDTO> getGamesByListID(Pageable pageable, String listId);
    GameListFullReturnDTO getGameListByID(String gameListID);
    Page<GameListReturnDTO> getLatestGamesByListID(Pageable pageable, String listId);
    GameListGameAndConsolesDTO getGameInfoByGameListID(String gameListId);
    Page<GenreCountDTO> getAllGameListGenresByUserId(String tokenJWT, Pageable pageable);
    CountGameListReturnDTO countGamesByListID(String listId);
    ArrayList<GameListBulkReturnDTO> addBulkGamesToList(GameListBulkCreateDTO data);
    GameListFullReturnDTO addGameList(GameListDTO data);
    GameListFullReturnDTO updateGameList(GameListUpdateRequestDTO data, String gameListId);
    void deleteGameList(DeleteGameListDTO data);
}
