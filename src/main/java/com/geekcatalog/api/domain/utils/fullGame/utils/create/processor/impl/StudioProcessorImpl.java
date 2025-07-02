package com.geekcatalog.api.domain.utils.fullGame.utils.create.processor.impl;

import com.geekcatalog.api.dto.country.CountryReturnDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.geekcatalog.api.domain.gameStudio.DTO.GameStudioDTO;
import com.geekcatalog.api.domain.studios.DTO.StudioDTO;
import com.geekcatalog.api.domain.studios.DTO.StudioReturnDTO;
import com.geekcatalog.api.domain.studios.DTO.StudioReturnFullGameInfo;
import com.geekcatalog.api.domain.utils.API.IGDB.DTO.CompanyReturnDTO;
import com.geekcatalog.api.domain.utils.API.IGDB.utils.StudioCountryMapperFromIGDB;
import com.geekcatalog.api.domain.utils.API.IGDB.utils.StudioDTOFormatterFromIGDB;
import com.geekcatalog.api.domain.utils.fullGame.utils.create.processor.StudioProcessor;
import com.geekcatalog.api.service.GameStudioService;
import com.geekcatalog.api.service.StudioService;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.geekcatalog.api.infra.utils.stringFormatter.StringFormatter.capitalizeEachWord;
import static com.geekcatalog.api.infra.utils.stringFormatter.StringFormatter.normalizeString;

@Service
public class StudioProcessorImpl implements StudioProcessor {
    @Autowired
    private GameStudioService gameStudioService;
    @Autowired
    private StudioCountryMapperFromIGDB studioCountryMapperFromIGDB;
    @Autowired
    private StudioService studioService;
    @Autowired
    private StudioDTOFormatterFromIGDB studioDTOFormatterFromIGDB;
    private static final Logger logger = LoggerFactory.getLogger(StudioProcessorImpl.class);

    @Override
    public void addGameStudio(List<StudioReturnFullGameInfo> newGameStudios, String gameId, StudioReturnDTO studio) {
        var gameStudioDTO = new GameStudioDTO(gameId, studio.id().toString());
        var gameStudioCreated = gameStudioService.createGameStudio(gameStudioDTO);
        newGameStudios.add(new StudioReturnFullGameInfo(gameStudioCreated.id(), gameStudioCreated.studioName()));
    }

    @Override
    public Map<String, CountryReturnDTO> buildNormalizedStudiosCountryMap(List<CompanyReturnDTO> studios) {
        return studioCountryMapperFromIGDB.buildNormalizedStudiosCountryMap(studios);
    }

    @Override
    public Map<String, StudioReturnDTO> fetchStudiosWithId(List<StudioDTO> studiosDTO) {
        return studioService.getStudiosByName(studiosDTO)
                .stream()
                .collect(Collectors.toMap(
                        studio -> normalizeString(studio.name()),
                        studio -> studio
                ));
    }

    @Override
    public StudioReturnDTO handleStudioCreationOrFetch(CompanyReturnDTO studioData, String gameId, Map<String, CountryReturnDTO> normalizedCountriesWithId, Map<String, StudioReturnDTO> normalizedStudiosWithId) {
        StudioReturnDTO studio = normalizedStudiosWithId.get(studioData.companyName());
        if (studio != null) {
            logger.info("Estúdio '{}' já existe. Associando ao jogo ID: {}", studio.name(), gameId);
            return studio;
        }

        logger.info("Criando novo estúdio '{}'", capitalizeEachWord(studioData.companyName()));

        var studioCountry = normalizeString(studioData.countryInfo().name().common());
        var country = normalizedCountriesWithId.get(studioCountry);

        var newStudio = new StudioDTO(capitalizeEachWord(studioData.companyName()), country.id());

        return studioService.createStudio(newStudio);
    }

    @Override
    public List<StudioDTO> mapStudiosToDTO(List<CompanyReturnDTO> studios, Map<String, CountryReturnDTO> normalizedCountriesWithId) {
        return studioDTOFormatterFromIGDB.mapStudiosToDTO(studios, normalizedCountriesWithId);
    }
}
