package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.model.UserDTO;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.dto.UserCreateDTO;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.http.HttpStatus;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final AppUserRepository users;

    public UserController(AppUserRepository users) {
        this.users = users;
    }

    // ✅ FIXED: Safe user listing — returns DTO only (no passwords, no emails)
    @GetMapping
    public List<UserDTO> allUsers() {
        return users.findAll().stream()
                .map(user -> new UserDTO(user.getId(), user.getUsername()))
                .collect(Collectors.toList());
    }

    // ✅ FIXED: Secure user creation (role and admin fields are server-controlled)
    @PostMapping
    public ResponseEntity<?> create(@Valid @RequestBody UserCreateDTO dto) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

        AppUser user = AppUser.builder()
                .username(dto.getUsername())
                .password(encoder.encode(dto.getPassword()))
                .email(dto.getEmail())
                .role("USER")          // Force safe role
                .isAdmin(false)        // Prevent privilege escalation
                .build();

        users.save(user);

        Map<String, Object> response = new HashMap<>();
        response.put("id", user.getId());
        response.put("username", user.getUsername());
        response.put("email", user.getEmail());
        response.put("role", "USER");
        response.put("isAdmin", false);

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // ⚠️ NOTE: This endpoint is intentionally kept for API9 vulnerability testing
    // It is insecure by design for the OWASP lab exercise.
    @GetMapping("/search")
    public List<AppUser> search(@RequestParam String q) {
        return users.search(q);
    }

    // ⚠️ NOTE: This endpoint remains intentionally insecure for API5 test case
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Long id) {
        users.deleteById(id);
        Map<String, String> response = new HashMap<>();
        response.put("status", "deleted");
        return ResponseEntity.ok(response);
    }
}
