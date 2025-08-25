package com.geekcatalog.api.infra.exceptions;

public class DTOValidationException extends RuntimeException {
    public DTOValidationException(String message) {
        super(message);
    }
}
