package com.geekcatalog.api.service;

import com.geekcatalog.api.domain.country.Country;

public interface EntityHandlerService {
    Country getCountryById(String id);
}
