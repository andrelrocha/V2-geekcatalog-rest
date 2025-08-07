package com.geekcatalog.api.service;


import com.geekcatalog.api.domain.user.UseCase.CreateUser;
import com.geekcatalog.api.dto.user.UserDTO;
import com.geekcatalog.api.dto.user.UserReturnDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final CreateUser createUser;

    public UserReturnDTO create(UserDTO data) {
        return createUser.create(data);
    }
}