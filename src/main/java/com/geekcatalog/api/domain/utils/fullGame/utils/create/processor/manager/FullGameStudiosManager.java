package com.geekcatalog.api.domain.utils.fullGame.utils.create.processor.manager;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.studios.DTO.StudioReturnFullGameInfo;
import com.geekcatalog.api.domain.utils.API.IGDB.DTO.CompanyReturnDTO;
import com.geekcatalog.api.domain.utils.fullGame.utils.create.processor.StudioProcessor;

import java.util.ArrayList;
import java.util.List;

@Component
public class FullGameStudiosManager {
    @Autowired
    public StudioProcessor studioProcessor;

    public ArrayList<StudioReturnFullGameInfo> manageFullGameStudios(List<CompanyReturnDTO> studios, String gameId) {
        var normalizedCountriesWithId = studioProcessor.buildNormalizedStudiosCountryMap(studios);
        var studiosDTO = studioProcessor.mapStudiosToDTO(studios, normalizedCountriesWithId);
        var studiosMapWithId = studioProcessor.fetchStudiosWithId(studiosDTO);

        var newGameStudios = new ArrayList<StudioReturnFullGameInfo>();

        for (CompanyReturnDTO studioData : studios) {
            var studio = studioProcessor.handleStudioCreationOrFetch(studioData, gameId, normalizedCountriesWithId, studiosMapWithId);

            studioProcessor.addGameStudio(newGameStudios, gameId, studio);
        }

        return newGameStudios;
    }
}
