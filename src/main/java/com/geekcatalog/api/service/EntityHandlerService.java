package com.geekcatalog.api.service;

import com.geekcatalog.api.domain.country.Country;
import com.geekcatalog.api.domain.role.Role;
import com.geekcatalog.api.domain.user.User;

import java.util.List;

public interface EntityHandlerService {
    Country getCountryById(String id);

    User getUserById(String id);

    Role getRoleById(String id);
    List<Role> getRolesByNames(List<String> names);
}
