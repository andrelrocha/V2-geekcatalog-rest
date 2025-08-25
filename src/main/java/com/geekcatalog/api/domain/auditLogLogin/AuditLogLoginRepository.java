package com.geekcatalog.api.domain.auditLogLogin;

import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditLogLoginRepository extends JpaRepository<AuditLogLogin, String> {
}
