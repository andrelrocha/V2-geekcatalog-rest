package com.geekcatalog.api.service.old.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import com.geekcatalog.api.infra.utils.sheets.xlsx.ExportGamesOnListToSheets;
import com.geekcatalog.api.infra.utils.sheets.xlsx.GamesOnUserListInfoDTO;
import com.geekcatalog.api.infra.utils.sheets.xlsx.GetFullGamesOnListByUser;
import com.geekcatalog.api.infra.utils.sheets.xlsx.ImportGamesOnSheetToDB;
import com.geekcatalog.api.service.old.SpreadsheetService;

import java.io.ByteArrayInputStream;
import java.util.List;

@Service
public class SpreadSheetServiceImpl implements SpreadsheetService {
    @Autowired
    private GetFullGamesOnListByUser getFullGamesOnListByUser;
    @Autowired
    private ExportGamesOnListToSheets exportGamesOnListToSheets;
    @Autowired
    private ImportGamesOnSheetToDB importGamesOnSheetToDB;

    @Override
    public ByteArrayInputStream exportGamesOnListRegularUserToXlsx(String userId) {
        var allGamesOnUserLists = getFullGamesOnListByUser.getAllGamesByUserId(userId);
        return exportGamesOnListToSheets.exportToXLSX(allGamesOnUserLists, false);
    }

    @Override
    public ByteArrayInputStream exportGamesOnListWithIdXlsx(String userId) {
        var allGamesOnUserLists = getFullGamesOnListByUser.getAllGamesByUserId(userId);
        return exportGamesOnListToSheets.exportToXLSX(allGamesOnUserLists, true);
    }

    @Override
    public List<GamesOnUserListInfoDTO> saveNewGameDataOnDB(MultipartFile file, String userId) {
        return importGamesOnSheetToDB.saveNewGameDataOnDB(file, userId);
    }
}
