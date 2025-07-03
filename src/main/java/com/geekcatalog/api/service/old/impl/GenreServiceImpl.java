package com.geekcatalog.api.service.old.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import com.geekcatalog.api.domain.genres.DTO.GenreDTO;
import com.geekcatalog.api.domain.genres.DTO.GenreReturnDTO;
import com.geekcatalog.api.domain.genres.useCase.CreateGenre;
import com.geekcatalog.api.domain.genres.useCase.GetAllGenres;
import com.geekcatalog.api.domain.genres.useCase.GetGenresIdByName;
import com.geekcatalog.api.service.old.GenreService;

import java.util.ArrayList;
import java.util.List;

@Service
public class GenreServiceImpl implements GenreService {
    @Autowired
    private CreateGenre createGenre;
    @Autowired
    private GetAllGenres getAllGenres;
    @Autowired
    private GetGenresIdByName getGenresIdByName;

    @Override
    public GenreReturnDTO createGenre(GenreDTO data) {
        return createGenre.createGenre(data);
    }

    @Override
    public Page<GenreReturnDTO> getAllGenres(Pageable pageable) {
        var genres = getAllGenres.getAllGenres(pageable);
        return genres;
    }

    @Override
    public List<GenreReturnDTO> getGenresByName(ArrayList<GenreDTO> data) {
        return getGenresIdByName.getGenresByName(data);
    }
}
