package com.geekcatalog.api.dto.utils.api.IGDB;

public record CountryInfo(Name name, String cca2) {
    public record Name(String common) {}
}
