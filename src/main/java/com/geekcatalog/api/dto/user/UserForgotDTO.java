package com.geekcatalog.api.dto.user;

import java.time.LocalDateTime;

public record UserForgotDTO(
        String tokenMail,
        LocalDateTime tokenExpiration)
{ }
