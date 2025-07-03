package com.geekcatalog.api.service.old.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.geekcatalog.api.domain.utils.API.IGDB.GetGameInfoOnIGDB;
import com.geekcatalog.api.domain.utils.API.IGDB.DTO.IGDBQueryInfoDTO;
import com.geekcatalog.api.domain.utils.API.IGDB.DTO.IGDBResponseFullInfoDTO;
import com.geekcatalog.api.domain.utils.fullGame.DTO.CreateFullGameDTO;
import com.geekcatalog.api.domain.utils.fullGame.DTO.FullGameReturnDTO;
import com.geekcatalog.api.domain.utils.fullGame.useCase.CreateFullGameAdmin;
import com.geekcatalog.api.service.old.IGDBService;

@Service
public class IGDBServiceImpl implements IGDBService {
    @Autowired
    private CreateFullGameAdmin createFullGameAdmin;
    @Autowired
    private GetGameInfoOnIGDB getGameInfoOnIGDB;
    @Override
    public IGDBResponseFullInfoDTO fetchGameDetails(IGDBQueryInfoDTO queryInfo) {
        return getGameInfoOnIGDB.fetchGameDetails(queryInfo);
    }

    @Override
    public FullGameReturnDTO createGameFromIGDBInfo(CreateFullGameDTO data) {
        return createFullGameAdmin.createGameFromIGDBInfo(data);
    }
}
