package com.geekcatalog.api.service;


import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import com.geekcatalog.api.domain.studios.DTO.StudioDTO;
import com.geekcatalog.api.domain.studios.DTO.StudioReturnDTO;

import java.util.List;

public interface StudioService {
    Page<StudioReturnDTO> getAllStudios(Pageable pageable);
    StudioReturnDTO createStudio(StudioDTO data);
    List<StudioReturnDTO> getStudiosByName(List<StudioDTO> data);
}
