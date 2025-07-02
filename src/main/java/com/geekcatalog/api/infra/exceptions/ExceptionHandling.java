package com.geekcatalog.api.infra.exceptions;

import com.geekcatalog.api.dto.utils.ApiResponseDTO;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.LockedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

import javax.naming.AuthenticationException;
import java.nio.file.AccessDeniedException;
import java.sql.SQLException;
import java.util.List;

@RestControllerAdvice
public class ExceptionHandling {

    @ExceptionHandler(EntityNotFoundException.class)
    public ResponseEntity<ApiResponseDTO<?>> handleEntityNotFoundException() {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(ApiResponseDTO.failure("EntityNotFoundException", "Resource not found."));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiResponseDTO<?>> handleIllegalArgumentException(IllegalArgumentException ex) {
        return ResponseEntity.badRequest()
                .body(ApiResponseDTO.failure("IllegalArgumentException", ex.getMessage()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponseDTO<?>> handleValidationExceptions(MethodArgumentNotValidException ex) {
        List<String> errors = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(error -> String.format("Field '%s': %s", error.getField(), error.getDefaultMessage()))
                .toList();

        return ResponseEntity.badRequest()
                .body(ApiResponseDTO.failure("MethodArgumentNotValidException", String.join("; ", errors)));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiResponseDTO<?>> handleHttpMessageNotReadableException(HttpMessageNotReadableException ex) {
        if (ex.getCause() instanceof InvalidFormatException invalidFormatException) {
            if (invalidFormatException.getTargetType().equals(java.time.LocalDate.class)) {
                return ResponseEntity.badRequest()
                        .body(ApiResponseDTO.failure("InvalidDateFormat", "Date format is wrong. Use YYYY-MM-DD."));
            }
        }
        return ResponseEntity.badRequest()
                .body(ApiResponseDTO.failure("HttpMessageNotReadableException", ex.getMessage()));
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponseDTO<?>> handleBadCredentialsException() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ApiResponseDTO.failure("BadCredentialsException", "Invalid credentials."));
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiResponseDTO<?>> handleAuthenticationException() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ApiResponseDTO.failure("AuthenticationException", "Error while authenticating user."));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponseDTO<?>> handleAccessDeniedException() {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(ApiResponseDTO.failure("AccessDeniedException", "Access denied."));
    }

    @ExceptionHandler(LockedException.class)
    public ResponseEntity<ApiResponseDTO<?>> handleLockedException() {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(ApiResponseDTO.failure("LockedException", "Account locked."));
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ApiResponseDTO<?>> handleDataIntegrityViolationException(DataIntegrityViolationException ex) {
        Throwable rootCause = ex.getRootCause();
        if (rootCause instanceof SQLException sqlEx) {
            String sqlState = sqlEx.getSQLState();
            String errorMessage = sqlEx.getMessage();

            if ("23505".equals(sqlState)) {
                if (errorMessage.contains("user_email_key")) {
                    return ResponseEntity.badRequest()
                            .body(ApiResponseDTO.failure("UniqueConstraintViolation", "Duplicate email."));
                } else if (errorMessage.contains("users_username_key")) {
                    return ResponseEntity.badRequest()
                            .body(ApiResponseDTO.failure("UniqueConstraintViolation", "Duplicate username."));
                }
            }
        }

        return ResponseEntity.badRequest()
                .body(ApiResponseDTO.failure("DataIntegrityViolationException", "Data integrity violation."));
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<ApiResponseDTO<?>> handleMaxUploadSizeExceededException(MaxUploadSizeExceededException ex) {
        return ResponseEntity.badRequest()
                .body(ApiResponseDTO.failure("MaxUploadSizeExceededException", "Maximum upload size exceeded, please send a smaller file."));
    }

    @ExceptionHandler(InternalAuthenticationServiceException.class)
    public ResponseEntity<ApiResponseDTO<?>> handleInternalAuthenticationServiceException(InternalAuthenticationServiceException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiResponseDTO.failure("InternalAuthenticationServiceException", "Incorrect login or password."));
    }

    @ExceptionHandler(ValidationException.class)
    public ResponseEntity<ApiResponseDTO<?>> handleValidationException(ValidationException ex) {
        return ResponseEntity.badRequest()
                .body(ApiResponseDTO.failure("ValidationException", ex.getMessage()));
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiResponseDTO<?>> handleRuntimeException(RuntimeException ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponseDTO.failure("RuntimeException", "Internal Server Error: " + ex.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponseDTO<?>> handleException(Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponseDTO.failure("Exception", "Error: " + ex.getLocalizedMessage()));
    }

    private record DataValidationError(String field, String message) {
        public DataValidationError(FieldError error) {
            this(error.getField(), error.getDefaultMessage());
        }
    }
}