package com.geekcatalog.api.dto.user;

import java.time.LocalDate;

public record UserPublicReturnDTO(
                                  String name,
                                  LocalDate birthday,
                                  String countryName,
                                  String countryId) {

}
