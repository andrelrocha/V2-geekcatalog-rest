package com.geekcatalog.api.domain.auditLogLogin;

public enum LoginStatus {
    FAILURE(0),
    SUCCESS(1);

    private final int code;

    LoginStatus(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }

    public static LoginStatus fromCode(int code) {
        for (LoginStatus status : values()) {
            if (status.getCode() == code) {
                return status;
            }
        }
        throw new IllegalArgumentException("Invalid Code for Login Status: " + code);
    }
}
