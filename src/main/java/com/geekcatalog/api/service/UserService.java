package com.geekcatalog.api.service;


import com.geekcatalog.api.domain.user.UseCase.CreateUser;
import com.geekcatalog.api.dto.user.UserDTO;
import com.geekcatalog.api.dto.user.UserReturnDTO;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class UserService {
    private final CreateUser createUser;

    public UserReturnDTO create(UserDTO data) {
        return createUser.create(data);
    }
}