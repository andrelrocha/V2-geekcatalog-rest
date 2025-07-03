package com.geekcatalog.api.service.old;

import org.springframework.web.multipart.MultipartFile;
import com.geekcatalog.api.infra.utils.sheets.xlsx.GamesOnUserListInfoDTO;

import java.io.ByteArrayInputStream;
import java.util.List;

public interface SpreadsheetService {
    ByteArrayInputStream exportGamesOnListRegularUserToXlsx(String userId);
    ByteArrayInputStream exportGamesOnListWithIdXlsx(String userId);

    List<GamesOnUserListInfoDTO> saveNewGameDataOnDB(MultipartFile file, String userId);
}
