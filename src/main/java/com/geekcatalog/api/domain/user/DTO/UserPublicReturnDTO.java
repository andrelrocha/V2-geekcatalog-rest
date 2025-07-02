package com.geekcatalog.api.domain.user.DTO;

import java.time.LocalDate;
import java.util.UUID;

public record UserPublicReturnDTO(
                                  String name,
                                  LocalDate birthday,
                                  String countryName,
                                  String countryId) {

}
