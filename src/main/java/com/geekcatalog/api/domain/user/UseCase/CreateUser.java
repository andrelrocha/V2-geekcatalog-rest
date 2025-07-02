package com.geekcatalog.api.domain.user.UseCase;

import com.geekcatalog.api.domain.user.User;
import com.geekcatalog.api.domain.user.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.country.CountryRepository;
import com.geekcatalog.api.domain.user.DTO.UserCreateDTO;
import com.geekcatalog.api.domain.user.DTO.UserDTO;
import com.geekcatalog.api.domain.user.DTO.UserReturnDTO;
import com.geekcatalog.api.infra.exceptions.ValidationException;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

@Component
public class CreateUser {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private CountryRepository countryRepository;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public UserReturnDTO createUser(UserDTO data) {
        boolean userExists = userRepository.userExistsByLogin(data.login());

        if (userExists) {
            throw new ValidationException("Email on user creation already exists in our database");
        }

        var country = countryRepository.findById(data.countryId())
                .orElseThrow(() -> new ValidationException("No country was found fot the informed ID, during sign up."));

        var formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
        var formattedBirthday = LocalDate.parse(data.birthday().format(formatter));

        var updatedData = new UserDTO(
                data.login(),
                data.password(),
                data.name(),
                data.cpf(),
                data.phone(),
                formattedBirthday,
                data.countryId(),
                data.username(),
                data.twoFactorEnabled(),
                data.refreshTokenEnabled(),
                data.theme()
        );

        var createDTO = new UserCreateDTO(updatedData, country);

        var newUser = new User(createDTO);

        String encodedPassword = bCryptPasswordEncoder.encode(data.password());
        newUser.setPassword(encodedPassword);

        var userOnDb = userRepository.save(newUser);

        return new UserReturnDTO(userOnDb);
    }
}
