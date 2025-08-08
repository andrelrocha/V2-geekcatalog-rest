package com.geekcatalog.api.domain.user.useCase;

import com.geekcatalog.api.domain.user.User;
import com.geekcatalog.api.domain.user.UserRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class GetUserEntityById {
    @Autowired
    private UserRepository repository;

    public User getUserById(String id) {
        return repository.findById(id)
                .orElseThrow(() -> new ValidationException("No user (entity) was found for the provided ID."));
    }
}
