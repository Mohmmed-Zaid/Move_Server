package com.moveapp.movebackend.model.dto;

import lombok.Data;

/**
 * Standard API response wrapper for all endpoints
 * Provides consistent response format across the application
 */
@Data
public class ApiResponse<T> {
    private boolean success;
    private String message;
    private T data;
    private String error;
    private long timestamp;

    // Private constructor to enforce builder usage
    private ApiResponse() {}

    public static <T> ApiResponseBuilder<T> builder() {
        return new ApiResponseBuilder<>();
    }

    // Success response factory methods
    public static <T> ApiResponse<T> success(T data, String message) {
        return ApiResponse.<T>builder()
                .success(true)
                .message(message)
                .data(data)
                .timestamp(System.currentTimeMillis())
                .build();
    }

    public static <T> ApiResponse<T> success(T data) {
        return success(data, "Operation completed successfully");
    }

    public static ApiResponse<Void> success(String message) {
        return ApiResponse.<Void>builder()
                .success(true)
                .message(message)
                .timestamp(System.currentTimeMillis())
                .build();
    }

    // Error response factory methods
    public static <T> ApiResponse<T> error(String message, String errorCode) {
        return ApiResponse.<T>builder()
                .success(false)
                .message(message)
                .error(errorCode)
                .timestamp(System.currentTimeMillis())
                .build();
    }

    public static <T> ApiResponse<T> error(String message) {
        return error(message, "OPERATION_FAILED");
    }

    // Builder class
    public static class ApiResponseBuilder<T> {
        private boolean success;
        private String message;
        private T data;
        private String error;
        private long timestamp;

        public ApiResponseBuilder<T> success(boolean success) {
            this.success = success;
            return this;
        }

        public ApiResponseBuilder<T> message(String message) {
            this.message = message;
            return this;
        }

        public ApiResponseBuilder<T> data(T data) {
            this.data = data;
            return this;
        }

        public ApiResponseBuilder<T> error(String error) {
            this.error = error;
            return this;
        }

        public ApiResponseBuilder<T> timestamp(long timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public ApiResponse<T> build() {
            ApiResponse<T> response = new ApiResponse<>();
            response.success = this.success;
            response.message = this.message;
            response.data = this.data;
            response.error = this.error;
            response.timestamp = this.timestamp;
            return response;
        }
    }
}