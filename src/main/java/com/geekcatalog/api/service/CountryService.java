package com.geekcatalog.api.service;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import com.geekcatalog.api.domain.country.DTO.CountryReturnDTO;

import java.util.List;

public interface CountryService {
    Page<CountryReturnDTO> getAllCountries(Pageable pageable);
    List<CountryReturnDTO> getCountriesByName(List<String> names);
}
