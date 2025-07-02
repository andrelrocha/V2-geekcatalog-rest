package com.geekcatalog.api.domain.utils.fullGame.DTO;

import com.geekcatalog.api.domain.utils.API.IGDB.DTO.CompanyReturnDTO;

import java.util.List;

public record CreateFullGameDTO(String name, int metacritic, int yearOfRelease, List<String> consoles, List<String> genres, List<CompanyReturnDTO> studios) {
}