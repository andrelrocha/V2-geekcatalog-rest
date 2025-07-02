package com.geekcatalog.api.service;

import com.geekcatalog.api.domain.utils.API.IGDB.DTO.IGDBQueryInfoDTO;
import com.geekcatalog.api.domain.utils.API.IGDB.DTO.IGDBResponseFullInfoDTO;
import com.geekcatalog.api.domain.utils.fullGame.DTO.CreateFullGameDTO;
import com.geekcatalog.api.domain.utils.fullGame.DTO.FullGameReturnDTO;

public interface IGDBService {
    IGDBResponseFullInfoDTO fetchGameDetails(IGDBQueryInfoDTO queryInfo);
    FullGameReturnDTO createGameFromIGDBInfo(CreateFullGameDTO data);
}
