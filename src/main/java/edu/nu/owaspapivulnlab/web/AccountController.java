package edu.nu.owaspapivulnlab.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import io.github.bucket4j.*; // ADDED/KEPT IMPORT
import java.time.Duration; // ADDED/KEPT IMPORT
import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {
    
    // ✅ FIX 6.2 Step 1: Define a rate limit (5 requests per minute)
    // NOTE: Removed the duplicate definition of 'bucket' from the original input code.
    private final Bucket bucket = Bucket4j.builder()
            .addLimit(Bandwidth.classic(5, Refill.intervally(5, Duration.ofMinutes(1))))
            .build();

    private final AccountRepository accounts;
    private final AppUserRepository users;

    public AccountController(AccountRepository accounts, AppUserRepository users) {
        this.accounts = accounts;
        this.users = users;
    }

    // ✅ Fixed: Enforce ownership before returning balance
    @GetMapping("/{id}/balance")
    public ResponseEntity<?> balance(@PathVariable Long id, Authentication auth) {
        Account a = accounts.findById(id).orElseThrow(() -> new RuntimeException("Account not found"));
        AppUser me = users.findByUsername(auth.getName()).orElseThrow();

        if (!a.getOwnerUserId().equals(me.getId())) {
            return ResponseEntity.status(403).body(Map.of("error", "Forbidden: not your account"));
        }

        return ResponseEntity.ok(Map.of("balance", a.getBalance()));
    }

    // ✅ Fixed: Added Rate Limiting + Ownership Check + Input Validation
    @PostMapping("/{id}/transfer")
    public ResponseEntity<?> transfer(@PathVariable Long id,
                                      @RequestParam Double amount,
                                      Authentication auth) {

        // ✅ FIX 6.2 Step 2: Apply Rate Limiting check before processing
        if (bucket.tryConsume(1) == false) {
            // Using the requested specific error message:
            return ResponseEntity.status(429).body(Map.of("error", "Too many requests"));
        }

        AppUser me = users.findByUsername(auth.getName()).orElseThrow();
        Account a = accounts.findById(id).orElseThrow(() -> new RuntimeException("Account not found"));

        if (!a.getOwnerUserId().equals(me.getId())) {
            return ResponseEntity.status(403).body(Map.of("error", "Forbidden"));
        }

        if (amount == null || amount <= 0 || amount > a.getBalance()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid amount"));
        }

        a.setBalance(a.getBalance() - amount);
        accounts.save(a);

        return ResponseEntity.ok(Map.of("status", "ok", "remaining", a.getBalance()));
    }

    // ✅ Safe: Only returns accounts belonging to logged-in user
    @GetMapping("/mine")
    public Object mine(Authentication auth) {
        AppUser me = users.findByUsername(auth != null ? auth.getName() : "anonymous").orElse(null);
        return me == null ? Collections.emptyList() : accounts.findByOwnerUserId(me.getId());
    }
}