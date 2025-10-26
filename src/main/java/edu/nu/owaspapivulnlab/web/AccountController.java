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

    // Fixed: Enforce ownership before returning balance (robust against nulls/IAE)
    @GetMapping("/{id}/balance")
    public ResponseEntity<?> balance(@PathVariable("id") Long id, Authentication auth) {
        // Extract authenticated user from JWT token
        if (auth == null || auth.getName() == null) {
            return ResponseEntity.status(401).body(Collections.singletonMap("error", "Authentication required"));
        }
        
        // Find the authenticated user
        AppUser currentUser = users.findByUsername(auth.getName())
            .orElseThrow(() -> new RuntimeException("User not found"));
        
        // Find the requested account
        Account account = accounts.findById(id)
            .orElseThrow(() -> new RuntimeException("Account not found"));
        
        // AUTHORIZATION CHECK - Verify account belongs to authenticated user
        if (!account.getOwnerUserId().equals(currentUser.getId())) {
            return ResponseEntity.status(403).body(Collections.singletonMap("error", "Access denied - Account does not belong to you"));
        }
        
        // Return balance only if user owns the account
        return ResponseEntity.ok(Collections.singletonMap("balance", account.getBalance()));
    }

    // ✅ Fixed: Added Rate Limiting + Ownership Check + Input Validation
 // ✅ Fixed: Match POST /api/accounts/transfer and handle JSON body with validation
@PostMapping("/transfer")
public ResponseEntity<?> transfer(@RequestBody Map<String, Object> body, Authentication auth) {

    // ✅ Rate limiting
    if (!bucket.tryConsume(1)) {
        return ResponseEntity.status(429).body(Map.of("error", "Too many requests"));
    }

    // ✅ Authentication required
    if (auth == null || auth.getName() == null) {
        return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
    }

    // ✅ Validate input presence
   if (!body.containsKey("fromAccountId") || !body.containsKey("toAccountId") || !body.containsKey("amount")) {
    return ResponseEntity.badRequest().body(Map.of("error", "Invalid input - Missing required field"));
}
    Long fromId, toId;
    Double amount;

    try {
        fromId = Long.parseLong(body.get("fromAccountId").toString());
        toId = Long.parseLong(body.get("toAccountId").toString());
        amount = Double.parseDouble(body.get("amount").toString());
    } catch (NumberFormatException e) {
        return ResponseEntity.badRequest().body(Map.of("error", "Invalid account ID"));
    }

    // ✅ Amount validation
    if (amount <= 0) {
        return ResponseEntity.badRequest().body(Map.of("error", "Invalid input - amount must be positive"));
    }
    if (amount > 1_000_000) {
        return ResponseEntity.badRequest().body(Map.of("error", "Amount exceeds limit"));
    }

    // ✅ Load authenticated user and accounts
    AppUser me = users.findByUsername(auth.getName()).orElseThrow();
    Account fromAcc = accounts.findById(fromId).orElseThrow(() -> new RuntimeException("Account not found"));
    Account toAcc = accounts.findById(toId).orElseThrow(() -> new RuntimeException("Account not found"));

    // ✅ Ownership check
    if (!fromAcc.getOwnerUserId().equals(me.getId())) {
        return ResponseEntity.status(403).body(Map.of("error", "Forbidden"));
    }

    if (fromAcc.getBalance() < amount) {
        return ResponseEntity.badRequest().body(Map.of("error", "Insufficient balance"));
    }

    // ✅ Perform transfer
    fromAcc.setBalance(fromAcc.getBalance() - amount);
    toAcc.setBalance(toAcc.getBalance() + amount);
    accounts.save(fromAcc);
    accounts.save(toAcc);

    return ResponseEntity.ok(Map.of("status", "ok", "remaining", fromAcc.getBalance()));
}



    // ✅ Safe: Only returns accounts belonging to logged-in user
    @GetMapping("/mine")
    public Object mine(Authentication auth) {
        AppUser me = users.findByUsername(auth != null ? auth.getName() : "anonymous").orElse(null);
        return me == null ? Collections.emptyList() : accounts.findByOwnerUserId(me.getId());
    }
}