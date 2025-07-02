package com.geekcatalog.api.service;

import org.springframework.web.servlet.ModelAndView;
import com.geekcatalog.api.domain.utils.API.IGDB.DTO.IGDBQueryRequestDTO;

public interface ViewService {
    ModelAndView showLoginOptions();
    ModelAndView createGameFromIGDB(IGDBQueryRequestDTO data);
    ModelAndView selectGame();
    ModelAndView signIn();
}
