/**
 * Sample 1: Low Complexity (Clean & Secure)
 * Language: Java
 * Purpose: Demonstrates robust, thread-safe, secure code adhering to Java & OWASP best practices.
 * Expected Score: 100/100 Health Score (Clean compilation, zero vulnerabilities).
 */

import java.math.BigDecimal;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

public class SecureBankTransfer {
    private final String accountId;
    private BigDecimal balance;

    public SecureBankTransfer(String accountId, BigDecimal initialBalance) {
        if (accountId == null || accountId.trim().isEmpty()) {
            throw new IllegalArgumentException("Invalid account ID");
        }
        this.accountId = accountId;
        this.balance = initialBalance != null ? initialBalance : BigDecimal.ZERO;
    }

    public synchronized void transfer(BigDecimal amount) {
        if (amount != null && amount.compareTo(BigDecimal.ZERO) > 0 && this.balance.compareTo(amount) >= 0) {
            this.balance = this.balance.subtract(amount);
        }
    }

    public static byte[] hashAuditTrail(String auditData) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(auditData.getBytes(StandardCharsets.UTF_8));
    }
}
