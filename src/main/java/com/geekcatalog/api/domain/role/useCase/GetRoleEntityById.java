package com.geekcatalog.api.domain.role.useCase;

import com.geekcatalog.api.domain.role.Role;
import com.geekcatalog.api.domain.role.RoleRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class GetRoleEntityById {
    @Autowired
    private RoleRepository repository;

    public Role getRoleById(String id) {
        return repository.findById(id)
                .orElseThrow(() -> new ValidationException("No role was found from the provided ID."));
    }
}
