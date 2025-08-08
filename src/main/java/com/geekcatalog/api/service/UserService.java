package com.geekcatalog.api.service;


import com.geekcatalog.api.domain.user.UseCase.CreateUser;
import com.geekcatalog.api.domain.user.UseCase.GetPublicInfo;
import com.geekcatalog.api.domain.user.UseCase.GetUserByTokenJWT;
import com.geekcatalog.api.domain.user.UseCase.UpdateUser;
import com.geekcatalog.api.dto.user.UserDTO;
import com.geekcatalog.api.dto.user.UserPublicReturnDTO;
import com.geekcatalog.api.dto.user.UserReturnDTO;
import com.geekcatalog.api.dto.user.UserUpdateDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final CreateUser createUser;
    private final GetPublicInfo getPublicInfo;
    private final GetUserByTokenJWT getUserByTokenJWT;
    private final UpdateUser updateUser;

    public UserReturnDTO create(UserDTO data) {
        return createUser.create(data);
    }

    public UserPublicReturnDTO getPublicInfoByUserId(String userId) {
        return getPublicInfo.getPublicInfoByUserId(userId);
    }

    public UserReturnDTO getUserByJWT(String tokenJWT) {
        return getUserByTokenJWT.getUserByIdClaim(tokenJWT);
    }

    public UserReturnDTO updateUserInfo(UserUpdateDTO dto, String userId) {
        return updateUser.updateUserInfo(dto, userId);
    }
}