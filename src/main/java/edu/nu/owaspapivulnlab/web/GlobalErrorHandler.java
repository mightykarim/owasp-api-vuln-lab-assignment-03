package edu.nu.owaspapivulnlab.web;

import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.HashMap;
import java.util.Map;

// FIXED (Error Handling & Logging): Error responses no longer expose internal exception details.
@ControllerAdvice
public class GlobalErrorHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> all(Exception e) {
        // Log the exception details here for server-side tracking (not shown to client)
        // System.err.println("SERVER ERROR: " + e.getClass().getName() + " - " + e.getMessage());

        Map<String, String> errorMap = new HashMap<>();
        // FIX: Return a generic message instead of e.getClass().getName() and e.getMessage()
        errorMap.put("error", "Internal server error");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorMap);
    }

    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<?> db(DataAccessException e) {
        // Log the database exception details here
        // System.err.println("DATABASE ERROR: " + e.getMessage());

        Map<String, String> errorMap = new HashMap<>();
        // FIX: Return a generic message instead of e.getMessage()
        errorMap.put("error", "Database error occurred");
        return ResponseEntity.status(500).body(errorMap);
    }
}