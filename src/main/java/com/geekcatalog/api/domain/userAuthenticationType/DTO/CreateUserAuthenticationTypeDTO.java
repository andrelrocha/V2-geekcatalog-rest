package com.geekcatalog.api.domain.userAuthenticationType.DTO;

import com.geekcatalog.api.domain.authenticationType.AuthenticationType;
import com.geekcatalog.api.domain.user.User;

public record CreateUserAuthenticationTypeDTO(AuthenticationType authenticationType, User user, String OAuthId) {
}
