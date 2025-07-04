package com.geekcatalog.api.domain.role.useCase;

import com.geekcatalog.api.domain.role.Role;
import com.geekcatalog.api.domain.role.RoleRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class GetListRoleEntitiesByNames {
    @Autowired
    private RoleRepository repository;

    public List<Role> getRolesByNames(List<String> names) {
        List<String> normalizedNames = names.stream()
                .map(name -> name.trim().toLowerCase())
                .toList();

        var cargos = repository.findAllByNamesIgnoreCaseAndTrimmed(normalizedNames);

        if (cargos.isEmpty()) {
            throw new ValidationException("No roles were found from the list of names provided as a parameter.");
        }

        return cargos;
    }
}
