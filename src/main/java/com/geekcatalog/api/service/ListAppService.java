package com.geekcatalog.api.service;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import com.geekcatalog.api.domain.listsApp.DTO.ListAppDTO;
import com.geekcatalog.api.domain.listsApp.DTO.ListAppReturnDTO;

public interface ListAppService {
    ListAppReturnDTO createListApp(ListAppDTO data);
    ListAppReturnDTO updateListApp(ListAppDTO data, String listId);
    void deleteList(String listId, String tokenJWT);
    ListAppReturnDTO getList(String listId);
    Page<ListAppReturnDTO> getAllListsByUserId(String userId, Pageable pageable);
    Page<ListAppReturnDTO> getAllPublicListsByUserId(String userId, Pageable pageable);
    Page<ListAppReturnDTO> getAllListsWithReadPermission(String userId, Pageable pageable);
}
