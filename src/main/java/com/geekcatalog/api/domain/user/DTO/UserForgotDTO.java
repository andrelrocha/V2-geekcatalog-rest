package com.geekcatalog.api.domain.user.DTO;

import java.time.LocalDateTime;

public record UserForgotDTO(
        String tokenMail,
        LocalDateTime tokenExpiration)
{ }
