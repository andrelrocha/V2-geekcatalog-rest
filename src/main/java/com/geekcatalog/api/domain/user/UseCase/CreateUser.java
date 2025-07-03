package com.geekcatalog.api.domain.user.UseCase;

import com.geekcatalog.api.domain.user.User;
import com.geekcatalog.api.domain.user.UserRepository;
import com.geekcatalog.api.dto.user.UserReturnDTO;
import com.geekcatalog.api.dto.user.UserDTO;
import com.geekcatalog.api.service.EntityHandlerService;
import com.geekcatalog.api.infra.exceptions.ValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class CreateUser {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private EntityHandlerService entityHandlerService;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public UserReturnDTO signUp(UserDTO data) {
        boolean userExistsByEmail = userRepository.userExistsByEmail(data.email());
        boolean userExistsByUsername = userRepository.userExistsByUsername(data.username());
        if (userExistsByEmail) {
            throw new ValidationException("Email on user creation already exists in our database");
        } else if(userExistsByUsername) {
            throw new ValidationException("Username on user creation already exists in our database");
        }

        var country = entityHandlerService.getCountryById(data.countryId());

        var newUser = new User(data, country);

        String encodedPassword = bCryptPasswordEncoder.encode(data.password());
        newUser.setPassword(encodedPassword);

        var userOnDb = userRepository.save(newUser);

        return new UserReturnDTO(userOnDb);
    }
}
