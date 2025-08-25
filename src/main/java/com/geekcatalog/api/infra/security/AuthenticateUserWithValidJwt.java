package com.geekcatalog.api.infra.security;

import com.geekcatalog.api.domain.user.User;
import com.geekcatalog.api.domain.user.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class AuthenticateUserWithValidJwt {
    @Autowired
    private UserRepository userRepository;

    public User findUserAuthenticated(String login) {
        return (User) userRepository.findByUsername(login);
    }

}

