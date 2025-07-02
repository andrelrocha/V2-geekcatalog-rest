package com.geekcatalog.api.service;

import com.geekcatalog.api.dto.country.CountryReturnDTO;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;

public interface CountryService {
    Page<CountryReturnDTO> getAllCountries(Pageable pageable);
    List<CountryReturnDTO> getCountriesByName(List<String> names);
}
