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

    // ✅ FIXED: Converts to DTO to prevent sensitive data exposure
    @GetMapping("/api/users")
    public List<UserDTO> allUsers() {
        return users.findAll().stream()
                .map(user -> new UserDTO(user.getId(), user.getUsername()))
                .collect(Collectors.toList());
    }

    // VULNERABILITY(API6: Mass Assignment) - binds role/isAdmin from client
    @PostMapping
    public ResponseEntity<?> create(@Valid @RequestBody UserCreateDTO dto) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        AppUser user = AppUser.builder()
                .username(dto.getUsername())
                .password(encoder.encode(dto.getPassword()))
                .email(dto.getEmail())
                .role("USER")
                .isAdmin(false)
                .build();
        users.save(user);
        Map<String, Object> response = new HashMap<>();
        response.put("id", user.getId());
        response.put("username", user.getUsername());
        response.put("email", user.getEmail());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // VULNERABILITY(API9: Improper Inventory + API8 Injection style): naive 'search' that can be abused for enumeration
    @GetMapping("/search")
    public List<AppUser> search(@RequestParam String q) {
        return users.search(q);
    }

    // VULNERABILITY(API3: Excessive Data Exposure) - returns all users including sensitive fields
    @GetMapping
    public List<AppUser> list() {
        return users.findAll();
    }

    // VULNERABILITY(API5: Broken Function Level Authorization) - allows regular users to delete anyone
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Long id) {
        users.deleteById(id);
        Map<String, String> response = new HashMap<>();
        response.put("status", "deleted");
        return ResponseEntity.ok(response);
    }
}
