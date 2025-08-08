package com.geekcatalog.api.domain.auditLogLogin.useCase;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import com.geekcatalog.api.domain.auditLogLogin.AuditLogLogin;
import com.geekcatalog.api.domain.auditLogLogin.AuditLogLoginRepository;
import com.geekcatalog.api.domain.auditLogLogin.LoginStatus;

import java.time.LocalDateTime;

@Component
public class RegisterAuditLog {
    @Autowired
    private AuditLogLoginRepository auditLogLoginRepository;


    //Isola a transação para que se torne independente em caso de exceção lançada que geraria o rollback quando fosse chamado em outra parte do código
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logLogin(String userName, HttpServletRequest request, LoginStatus loginStatus, String userAgent) {
        AuditLogLogin auditLog = new AuditLogLogin();

        auditLog.setUserName(userName);
        auditLog.setLoginTime(LocalDateTime.now());
        auditLog.setIpAddress(request.getRemoteAddr());
        auditLog.setLoginStatus(loginStatus);
        auditLog.setUserAgent(userAgent);
        auditLog.setHostName(request.getRemoteHost());
        auditLog.setServerName(request.getServerName());

        auditLogLoginRepository.save(auditLog);
    }
}
