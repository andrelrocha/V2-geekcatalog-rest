package com.geekcatalog.api.service;

import com.geekcatalog.api.domain.consoles.DTO.ConsoleReturnDTO;
import com.geekcatalog.api.domain.game.DTO.GameReturnDTO;
import com.geekcatalog.api.domain.genres.DTO.GenreReturnDTO;
import com.geekcatalog.api.domain.studios.DTO.StudioReturnFullGameInfo;
import com.geekcatalog.api.domain.utils.API.IGDB.DTO.CompanyReturnDTO;
import com.geekcatalog.api.domain.utils.fullGame.DTO.CreateFullGameDTO;

import java.util.ArrayList;
import java.util.List;

public interface FullGameService {
    GameReturnDTO manageCreateGameEntity(CreateFullGameDTO data);
    ArrayList<ConsoleReturnDTO> manageFullGameConsoles(List<String> consoles, String gameId);
    ArrayList<GenreReturnDTO> manageFullGameGenres(List<String> genres, String gameId);
    ArrayList<StudioReturnFullGameInfo> manageFullGameStudios(List<CompanyReturnDTO> studios, String gameId);
}
