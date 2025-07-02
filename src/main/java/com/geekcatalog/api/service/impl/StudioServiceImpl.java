package com.geekcatalog.api.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import com.geekcatalog.api.domain.studios.DTO.StudioDTO;
import com.geekcatalog.api.domain.studios.DTO.StudioReturnDTO;
import com.geekcatalog.api.domain.studios.useCase.CreateStudio;
import com.geekcatalog.api.domain.studios.useCase.GetAllStudios;
import com.geekcatalog.api.domain.studios.useCase.GetStudiosIdByName;
import com.geekcatalog.api.service.StudioService;

import java.util.List;

@Service
public class StudioServiceImpl implements StudioService {
    @Autowired
    private CreateStudio createStudio;
    @Autowired
    private GetAllStudios getAllStudios;
    @Autowired
    private GetStudiosIdByName getStudiosIdByName;

    @Override
    public Page<StudioReturnDTO> getAllStudios(Pageable pageable) {
        var studios = getAllStudios.getAllStudios(pageable);
        return studios;
    }

    @Override
    public StudioReturnDTO createStudio(StudioDTO data) {
        var newStudio = createStudio.createStudio(data);
        return newStudio;
    }

    @Override
    public List<StudioReturnDTO> getStudiosByName(List<StudioDTO> data) {
        return getStudiosIdByName.getStudiosByName(data);
    }
}
