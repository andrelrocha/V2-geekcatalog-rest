package com.geekcatalog.api.domain.utils.API.IGDB.utils;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.country.DTO.CountryReturnDTO;
import com.geekcatalog.api.domain.utils.API.IGDB.DTO.CompanyReturnDTO;
import com.geekcatalog.api.service.CountryService;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.geekcatalog.api.infra.utils.stringFormatter.StringFormatter.normalizeString;

@Component
public class StudioCountryMapperFromIGDB {
    @Autowired
    private CountryService countryService;

    public Map<String, CountryReturnDTO> buildNormalizedStudiosCountryMap(List<CompanyReturnDTO> studios) {
        var countryNames = extractCountryNames(studios);
        List<CountryReturnDTO> countries = countryService.getCountriesByName(countryNames);
        return countries.stream().collect(Collectors.toMap(
                country -> normalizeString(country.name()),
                country -> country
        ));
    }

    private List<String> extractCountryNames(List<CompanyReturnDTO> studios) {
        return studios.stream()
                .map(studio -> studio.countryInfo().name().common())
                .toList();
    }
}
