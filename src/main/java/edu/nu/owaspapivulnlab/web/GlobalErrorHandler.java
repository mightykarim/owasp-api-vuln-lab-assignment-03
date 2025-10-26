package edu.nu.owaspapivulnlab.web;

import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
public class GlobalErrorHandler {

    // 🔹 Bad request (invalid params, JSON parse errors)
    @ExceptionHandler({
        MethodArgumentTypeMismatchException.class,
        HttpMessageNotReadableException.class,
        MethodArgumentNotValidException.class
    })
    public ResponseEntity<?> handleBadRequest(Exception e) {
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("error", "Bad request");
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorMap);
    }

    // 🔹 Not found (missing resources)
    @ExceptionHandler({RuntimeException.class, ResponseStatusException.class})
    public ResponseEntity<?> handleNotFound(Exception e) {
        String msg = e.getMessage() != null ? e.getMessage().toLowerCase() : "";

        Map<String, String> errorMap = new HashMap<>();

        // Detect "not found" style errors safely
        if (msg.contains("not found") || msg.contains("no value present") || msg.contains("missing")) {
            errorMap.put("error", "Account not found");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorMap);
        }

        // Otherwise, treat as internal error
        errorMap.put("error", "Internal server error");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorMap);
    }

    // 🔹 Database issues
    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<?> db(DataAccessException e) {
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("error", "Database error occurred");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorMap);
    }

    // 🔹 Forbidden / illegal operations
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<?> illegalArg(IllegalArgumentException e) {
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("error", "Forbidden");
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorMap);
    }

    // 🔹 Catch-all fallback
    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> all(Exception e) {
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("error", "Internal server error");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorMap);
    }
    

}
