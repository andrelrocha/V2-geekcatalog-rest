package com.geekcatalog.api.domain.listsApp.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.listsApp.DTO.ListAppReturnDTO;
import com.geekcatalog.api.domain.listsApp.ListAppRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;

import java.util.UUID;

@Component
public class GetListByID {
    @Autowired
    private ListAppRepository repository;

    public ListAppReturnDTO getList(String listId) {
        var listIUUID = UUID.fromString(listId);
        var list = repository.findById(listIUUID)
                .orElseThrow(() -> new ValidationException("No List was found for the provided ID."));

        return new ListAppReturnDTO(list);
    }
}
