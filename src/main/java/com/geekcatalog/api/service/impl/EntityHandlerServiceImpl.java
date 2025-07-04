package com.geekcatalog.api.service.impl;

import com.geekcatalog.api.domain.country.Country;
import com.geekcatalog.api.domain.country.useCase.GetCountryEntityById;
import com.geekcatalog.api.domain.user.UseCase.GetUserEntityById;
import com.geekcatalog.api.domain.user.User;
import com.geekcatalog.api.service.EntityHandlerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class EntityHandlerServiceImpl implements EntityHandlerService {
    @Autowired
    private GetCountryEntityById getCountryEntityById;

    @Autowired
    private GetUserEntityById getUserEntityById;

    @Override
    public Country getCountryById(String id) {
        return getCountryEntityById.getCountryById(id);
    }

    @Override
    public User getUserById(String id) {
        return getUserEntityById.getUserById(id);
    }
}
