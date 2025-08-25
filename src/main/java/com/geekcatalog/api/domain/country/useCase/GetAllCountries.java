package com.geekcatalog.api.domain.country.useCase;

import com.geekcatalog.api.dto.country.CountryReturnDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.country.CountryRepository;

@Component
public class GetAllCountries {
    @Autowired
    private CountryRepository repository;

    public Page<CountryReturnDTO> getAllCountries(Pageable pageable) {
        return repository.findAllCountriesOrderedByName(pageable).map(CountryReturnDTO::new);
    }
}