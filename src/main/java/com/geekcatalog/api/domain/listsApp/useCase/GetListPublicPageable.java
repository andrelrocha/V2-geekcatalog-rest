package com.geekcatalog.api.domain.listsApp.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.listsApp.DTO.ListAppReturnDTO;
import com.geekcatalog.api.domain.listsApp.ListAppRepository;

import java.util.UUID;

@Component
public class GetListPublicPageable {
    @Autowired
    private ListAppRepository repository;

    public Page<ListAppReturnDTO> getAllPublicListsByUserId(String userId, Pageable pageable) {
        return repository.findAllListsPublicByUserId(pageable, userId).map(ListAppReturnDTO::new);
    }
}
