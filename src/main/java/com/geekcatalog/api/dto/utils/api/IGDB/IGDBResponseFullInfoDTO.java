package com.geekcatalog.api.dto.utils.api.IGDB;

import java.util.List;

public record IGDBResponseFullInfoDTO(String gameName, int yearOfRelease, String cover, List<String> genresName, List<String> platformsName, List<CompanyReturnDTO> involvedCompanies) {
}
