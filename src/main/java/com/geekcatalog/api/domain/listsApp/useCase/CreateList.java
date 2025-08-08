package com.geekcatalog.api.domain.listsApp.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.listsApp.DTO.ListAppCreateDTO;
import com.geekcatalog.api.domain.listsApp.DTO.ListAppDTO;
import com.geekcatalog.api.domain.listsApp.DTO.ListAppReturnDTO;
import com.geekcatalog.api.domain.listsApp.ListApp;
import com.geekcatalog.api.domain.listsApp.ListAppRepository;
import com.geekcatalog.api.domain.user.UserRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;

import java.util.UUID;

@Component
public class CreateList {
    @Autowired
    private ListAppRepository listAppRepository;
    @Autowired
    private UserRepository userRepository;

    public ListAppReturnDTO createListApp(ListAppDTO data) {
        var existsByNameAndUserId = listAppRepository.existsByName(data.name(), data.userId());

        if (existsByNameAndUserId) {
            throw new ValidationException("A list with this name already exists.");
        }

        var user = userRepository.findByIdToHandle(data.userId());

        if (user == null) {
            throw new ValidationException("No user was found with the provided ID during the list creation process.");
        }

        var listCreateDTO = new ListAppCreateDTO(data.name(), data.description(), data.visibility(), user);

        var listApp = new ListApp(listCreateDTO);

        var listAppOnDB = listAppRepository.save(listApp);

        return new ListAppReturnDTO(listAppOnDB);
    }
}
