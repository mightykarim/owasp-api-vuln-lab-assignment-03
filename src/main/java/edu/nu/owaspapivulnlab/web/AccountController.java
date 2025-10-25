package edu.nu.owaspapivulnlab.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountRepository accounts;
    private final AppUserRepository users;

    public AccountController(AccountRepository accounts, AppUserRepository users) {
        this.accounts = accounts;
        this.users = users;
    }

    // FIXED VULNERABILITY(API1: BOLA) - no check whether account belongs to caller
    @GetMapping("/{id}/balance")
    public ResponseEntity<?> balance(@PathVariable Long id, Authentication auth) {
        Account a = accounts.findById(id).orElseThrow(() -> new RuntimeException("Account not found"));
        AppUser me = users.findByUsername(auth.getName()).orElseThrow();
        if (!a.getOwnerUserId().equals(me.getId())) {
            return ResponseEntity.status(403).body(Map.of("error", "Forbidden: not your account"));
        }
        return ResponseEntity.ok(Map.of("balance", a.getBalance()));
    }

    // VULNERABILITY(API4: Unrestricted Resource Consumption) - no rate limiting on transfer
    // Fixed VULNERABILITY(API5/1): no authorization check on owner
    @PostMapping("/{id}/transfer")
    public ResponseEntity<?> transfer(@PathVariable Long id, @RequestParam Double amount, Authentication auth) {
        AppUser me = users.findByUsername(auth.getName()).orElseThrow();
        Account a = accounts.findById(id).orElseThrow(() -> new RuntimeException("Account not found"));
        if (!a.getOwnerUserId().equals(me.getId())) {
            return ResponseEntity.status(403).body(Map.of("error", "Forbidden"));
        }
        if (amount <= 0 || amount > a.getBalance()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid amount"));
        }
        a.setBalance(a.getBalance() - amount);
        accounts.save(a);
        return ResponseEntity.ok(Map.of("status", "ok", "remaining", a.getBalance()));
    }

    // Safe-ish helper to view my accounts (still leaks more than needed)
    @GetMapping("/mine")
    public Object mine(Authentication auth) {
        AppUser me = users.findByUsername(auth != null ? auth.getName() : "anonymous").orElse(null);
        return me == null ? Collections.emptyList() : accounts.findByOwnerUserId(me.getId());
    }
}
