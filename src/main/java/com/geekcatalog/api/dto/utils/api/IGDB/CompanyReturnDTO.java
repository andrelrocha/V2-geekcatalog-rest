package com.geekcatalog.api.dto.utils.api.IGDB;

public record CompanyReturnDTO(String companyName, boolean developer, boolean publisher, CountryInfo countryInfo) {
}
