package com.geekcatalog.api.domain.genres.DTO;

import com.geekcatalog.api.domain.genres.Genre;

import java.util.UUID;

public record GenreReturnDTO(UUID id, String name) {
    public GenreReturnDTO(Genre genre) {
        this(genre.getId(), genre.getName());
    }
}
