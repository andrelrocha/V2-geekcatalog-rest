package com.geekcatalog.api.domain.country.useCase;

import com.geekcatalog.api.domain.country.Country;
import com.geekcatalog.api.domain.country.CountryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class GetCountryEntityById {
    @Autowired
    private CountryRepository countryRepository;

    public Country getCountryById(String id) {
        return countryRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("No Country entity was found from the ID."));
    }
}
