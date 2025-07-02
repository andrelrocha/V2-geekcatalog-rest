package com.geekcatalog.api.domain.country.useCase;

import com.geekcatalog.api.dto.country.CountryReturnDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.country.CountryRepository;

import java.util.List;

@Component
public class GetCountriesByName {
    @Autowired
    private CountryRepository countryRepository;

    public List<CountryReturnDTO> getCountriesByName(List<String> names) {
        var namesNormalized = names.stream()
                .map(String::toLowerCase)
                .map(String::trim)
                .toList();
        var countries = countryRepository.findAllByNamesIgnoreCaseAndTrimmed(namesNormalized);

        return countries.stream()
                .map(CountryReturnDTO::new)
                .toList();
    }
}
