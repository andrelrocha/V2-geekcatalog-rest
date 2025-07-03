package com.geekcatalog.api.infra.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import com.geekcatalog.api.domain.user.UserRepository;

@Service
public class AuthenticateService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String login) throws UsernameNotFoundException {
        //caso inicial passando o email
        UserDetails userDetails = userRepository.findByEmail(login);
        if (userDetails == null) {
            userDetails = userRepository.findByUsername(login);
        }
        return userDetails;
    }
}
