package com.geekcatalog.api.dto.utils;

public record ApiResponseDTO<T>(
        T data,
        ErrorResponse error

) {
    public static <T> ApiResponseDTO<T> success(T data) {
        return new ApiResponseDTO<>(data, null);
    }

    public static <T> ApiResponseDTO<T> failure(String name, String message) {
        return new ApiResponseDTO<>(null,new ErrorResponse(name, message));
    }

    public record ErrorResponse(String name, String message) {}
}