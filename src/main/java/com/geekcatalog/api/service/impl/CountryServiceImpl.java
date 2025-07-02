package com.geekcatalog.api.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import com.geekcatalog.api.domain.country.DTO.CountryReturnDTO;
import com.geekcatalog.api.domain.country.useCase.GetAllCountries;
import com.geekcatalog.api.domain.country.useCase.GetCountriesByName;
import com.geekcatalog.api.service.CountryService;

import java.util.List;

@Service
public class CountryServiceImpl implements CountryService {
    @Autowired
    private GetAllCountries getAllCountries;
    @Autowired
    private GetCountriesByName getCountriesByName;

    @Override
    public Page<CountryReturnDTO> getAllCountries(Pageable pageable) {
        var countries = getAllCountries.getAllCountries(pageable);
        return countries;
    }

    @Override
    public List<CountryReturnDTO> getCountriesByName(List<String> names) {
        return getCountriesByName.getCountriesByName(names);
    }
}
