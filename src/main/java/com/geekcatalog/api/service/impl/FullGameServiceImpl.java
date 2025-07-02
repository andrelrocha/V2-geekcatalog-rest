package com.geekcatalog.api.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.geekcatalog.api.domain.consoles.DTO.ConsoleReturnDTO;
import com.geekcatalog.api.domain.game.DTO.GameReturnDTO;
import com.geekcatalog.api.domain.genres.DTO.GenreReturnDTO;
import com.geekcatalog.api.domain.studios.DTO.StudioReturnFullGameInfo;
import com.geekcatalog.api.domain.utils.API.IGDB.DTO.CompanyReturnDTO;
import com.geekcatalog.api.domain.utils.fullGame.DTO.CreateFullGameDTO;
import com.geekcatalog.api.domain.utils.fullGame.utils.create.processor.manager.FullGameConsolesManager;
import com.geekcatalog.api.domain.utils.fullGame.utils.create.processor.manager.FullGameCreateEntityManager;
import com.geekcatalog.api.domain.utils.fullGame.utils.create.processor.manager.FullGameGenresManager;
import com.geekcatalog.api.domain.utils.fullGame.utils.create.processor.manager.FullGameStudiosManager;
import com.geekcatalog.api.service.FullGameService;

import java.util.ArrayList;
import java.util.List;

@Service
public class FullGameServiceImpl implements FullGameService {
    @Autowired
    private FullGameCreateEntityManager gameCreateEntityManager;
    @Autowired
    private FullGameConsolesManager gameConsolesManager;
    @Autowired
    private FullGameGenresManager gameGenresManager;
    @Autowired
    private FullGameStudiosManager gameStudiosManager;

    @Override
    public GameReturnDTO manageCreateGameEntity(CreateFullGameDTO data) {
        return gameCreateEntityManager.manageCreateGameEntity(data);
    }

    @Override
    public ArrayList<ConsoleReturnDTO> manageFullGameConsoles(List<String> consoles, String gameId) {
        return gameConsolesManager.manageFullGameConsoles(consoles, gameId);
    }

    @Override
    public ArrayList<GenreReturnDTO> manageFullGameGenres(List<String> genres, String gameId) {
        return gameGenresManager.manageFullGameGenres(genres, gameId);
    }

    @Override
    public ArrayList<StudioReturnFullGameInfo> manageFullGameStudios(List<CompanyReturnDTO> studios, String gameId) {
        return gameStudiosManager.manageFullGameStudios(studios, gameId);
    }
}
