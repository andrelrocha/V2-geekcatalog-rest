package com.geekcatalog.api.infra.security;

public record AuthTokensDTO(String accessToken, String refreshToken) {
}
