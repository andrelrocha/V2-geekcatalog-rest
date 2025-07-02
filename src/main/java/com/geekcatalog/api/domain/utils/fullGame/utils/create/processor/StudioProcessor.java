package com.geekcatalog.api.domain.utils.fullGame.utils.create.processor;

import com.geekcatalog.api.domain.country.DTO.CountryReturnDTO;
import com.geekcatalog.api.domain.studios.DTO.StudioDTO;
import com.geekcatalog.api.domain.studios.DTO.StudioReturnDTO;
import com.geekcatalog.api.domain.studios.DTO.StudioReturnFullGameInfo;
import com.geekcatalog.api.domain.utils.API.IGDB.DTO.CompanyReturnDTO;

import java.util.List;
import java.util.Map;

public interface StudioProcessor {
    void addGameStudio(List<StudioReturnFullGameInfo> newGameStudios, String gameId, StudioReturnDTO studio);
    Map<String, CountryReturnDTO> buildNormalizedStudiosCountryMap(List<CompanyReturnDTO> studios);
    Map<String, StudioReturnDTO> fetchStudiosWithId(List<StudioDTO> studiosDTO);
    StudioReturnDTO handleStudioCreationOrFetch(CompanyReturnDTO studioData,
                                                String gameId,
                                                Map<String, CountryReturnDTO> normalizedCountriesWithId,
                                                Map<String, StudioReturnDTO> normalizedStudiosWithId);
    List<StudioDTO> mapStudiosToDTO(List<CompanyReturnDTO> studios, Map<String, CountryReturnDTO> normalizedCountriesWithId);
}
