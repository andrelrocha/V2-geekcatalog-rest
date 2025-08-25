package com.geekcatalog.api.dto.game;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public record GameDTO(@NotEmpty String name, String description, @NotNull Integer releaseYear) {
}
