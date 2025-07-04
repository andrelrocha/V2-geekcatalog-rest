package com.geekcatalog.api.service;

import com.geekcatalog.api.domain.country.Country;
import com.geekcatalog.api.domain.user.User;

public interface EntityHandlerService {
    Country getCountryById(String id);

    User getUserById(String id);
}
