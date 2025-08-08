package com.geekcatalog.api.dto.user;

import com.geekcatalog.api.dto.country.CountryReturnDTO;

import java.time.LocalDate;

public record UserPublicReturnDTO(String name,
                                  String username,
                                  LocalDate birthday,
                                  CountryReturnDTO country) {

}
