package com.geekcatalog.api.service;


import com.geekcatalog.api.domain.user.useCase.*;
import com.geekcatalog.api.dto.user.UserDTO;
import com.geekcatalog.api.dto.user.UserPublicReturnDTO;
import com.geekcatalog.api.dto.user.UserReturnDTO;
import com.geekcatalog.api.dto.user.UserUpdateDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final CreateUser createUser;
    private final DeleteUser deleteUser;
    private final GetPublicInfo getPublicInfo;
    private final GetUsers getUsers;
    private final UpdateUser updateUser;

    public UserReturnDTO create(UserDTO data) {
        return createUser.create(data);
    }

    public void deleteUser(String userId) {
        deleteUser.deleteUser(userId);
    }

    public UserPublicReturnDTO getPublicInfoByUserId(String userId) {
        return getPublicInfo.getPublicInfoByUserId(userId);
    }

    public Page<UserReturnDTO> getUsersPageable(
            Pageable pageable,
            String id,
            String email,
            String username,
            String roleId,
            String name
    ) {
        return getUsers.getUsersPageable(pageable, id, email, username, roleId, name);
    }

    public UserReturnDTO updateUserInfo(UserUpdateDTO dto, String userId) {
        return updateUser.updateUserInfo(dto, userId);
    }
}