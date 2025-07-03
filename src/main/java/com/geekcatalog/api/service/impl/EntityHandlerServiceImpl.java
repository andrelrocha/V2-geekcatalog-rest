package com.geekcatalog.api.service.impl;

import com.geekcatalog.api.domain.country.Country;
import com.geekcatalog.api.domain.country.useCase.GetCountryEntityById;
import com.geekcatalog.api.service.EntityHandlerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class EntityHandlerServiceImpl implements EntityHandlerService {
    @Autowired
    private GetCountryEntityById getCountryEntityById;

    @Override
    public Country getCountryById(String id) {
        return getCountryEntityById.getCountryById(id);
    }
}
