package com.geekcatalog.api.service;

import com.geekcatalog.api.domain.country.Country;
import com.geekcatalog.api.domain.country.useCase.GetCountryEntityById;
import com.geekcatalog.api.domain.role.Role;
import com.geekcatalog.api.domain.role.useCase.GetListRoleEntitiesByNames;
import com.geekcatalog.api.domain.role.useCase.GetRoleEntityById;
import com.geekcatalog.api.domain.user.User;
import com.geekcatalog.api.domain.user.useCase.GetUserEntityById;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class EntityHandlerService {
    private final GetCountryEntityById getCountryEntityById;
    private final GetRoleEntityById getRoleEntityById;
    private final GetListRoleEntitiesByNames getListRoleEntitiesByNames;
    private final GetUserEntityById getUserEntityById;

    public Country getCountryById(String id) {
        return getCountryEntityById.getCountryById(id);
    }

    public User getUserById(String id) {
        return getUserEntityById.getUserById(id);
    }

    public Role getRoleById(String id) {
        return getRoleEntityById.getRoleById(id);
    }

    public List<Role> getRolesByNames(List<String> names) {
        return getListRoleEntitiesByNames.getRolesByNames(names);
    }
}
