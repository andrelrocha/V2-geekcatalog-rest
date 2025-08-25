package com.geekcatalog.api.dto.country;

import com.geekcatalog.api.domain.country.Country;

public record CountryReturnDTO(
        String id,
        String nameCommon,
        String nameOfficial,
        String cca2,
        String cca3,
        String ccn3,
        String region,
        String subregion,
        String capital,
        String internationalPrefix,
        String countryCode,
        String currencyCode,
        String currencyName,
        String currencySymbol
) {
    public CountryReturnDTO(Country country) {
        this(
                country.getId(),
                country.getNameCommon(),
                country.getNameOfficial(),
                country.getCca2(),
                country.getCca3(),
                country.getCcn3(),
                country.getRegion(),
                country.getSubregion(),
                country.getCapital(),
                country.getInternationalPrefix(),
                country.getCountryCode(),
                country.getCurrencyCode(),
                country.getCurrencyName(),
                country.getCurrencySymbol()
        );
    }
}

