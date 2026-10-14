# Sample Inspection Scenarios & Test Payloads

This document details 6 standard inspection scenarios for testing syntax validation, compiler diagnostics, and deterministic security analysis across Python and Java in the **Smart Code Inspection Platform**.

---

## Quick Reference Matrix

| Scenario | Target File | Language | UI Pre-loaded Option | Expected Syntax | Expected Findings | Key Rules Tested |
| :---: | :--- | :---: | :---: | :---: | :---: | :--- |
| **1** | `secure_calculator.py` | Python | `python_valid` | `true` | `0` | None (Clean code) |
| **2** | `broken_syntax.py` | Python | Custom paste | `false` | `0` | SyntaxError (Line 4) |
| **3** | `vulnerable_service.py` | Python | `python_vulnerable` | `true` | `7` | `SEC-PY-001` to `SEC-PY-006` |
| **4** | `SecureBankTransfer.java` | Java | `java_valid` | `true` | `0` | None (Clean code) |
| **5** | `BrokenCompilerDemo.java` | Java | Custom paste | `false` | `0` | `javac` compiler errors |
| **6** | `LegacyPortalService.java` | Java | `java_vulnerable` | `true` | `6` | `SEC-JV-001` to `SEC-JV-005` |

---

## Scenario 1: Valid Python (Clean Math Engine)
- **Target File**: `secure_calculator.py`
- **Language**: Python
- **UI Dropdown**: `✅ Valid Python (Secure Code)`
- **Expected Validation Result**: `valid_syntax: true`
- **Expected Findings Count**: `0`

### Source Code
```python
import math
from typing import List, Union

def calculate_statistics(numbers: List[Union[int, float]]) -> dict:
    """Safely calculate basic statistical metrics without eval or unsafe execution."""
    if not numbers:
        return {"mean": 0.0, "variance": 0.0, "std_dev": 0.0}
    
    mean = sum(numbers) / len(numbers)
    variance = sum((x - mean) ** 2 for x in numbers) / len(numbers)
    std_dev = math.sqrt(variance)
    
    return {
        "count": len(numbers),
        "mean": round(mean, 4),
        "variance": round(variance, 4),
        "std_dev": round(std_dev, 4)
    }

if __name__ == "__main__":
    dataset = [12.5, 45.2, 78.1, 99.4, 32.0]
    results = calculate_statistics(dataset)
    print("Computed Statistics:", results)
```

---

## Scenario 2: Syntax-Broken Python
- **Target File**: `broken_syntax.py`
- **Language**: Python
- **UI Action**: Paste into editor and click **🔍 Validate Syntax**
- **Expected Validation Result**: `valid_syntax: false`
- **Expected Diagnostics**: `SyntaxError` on line 4 with column offset pointer and unclosed parenthesis notification.

### Source Code
```python
def calculate_discount(price, discount_percent):
    if discount_percent > 100:
        raise ValueError("Invalid discount")
    final_price = price * (1 - (discount_percent / 100)
    return final_price
```

---

## Scenario 3: Vulnerable Python (Multi-Flaw Inspection)
- **Target File**: `vulnerable_service.py`
- **Language**: Python
- **UI Dropdown**: `⚠️ Vulnerable Python (OWASP Flaws)`
- **Expected Validation Result**: `valid_syntax: true`
- **Expected Findings Count**: `7`
  - `SEC-PY-001` (Critical): Arbitrary code execution via `eval(user_param)`
  - `SEC-PY-002` (Critical): OS Command Injection via `subprocess.Popen(..., shell=True)`
  - `SEC-PY-003` (High): SQL Injection via `cursor.execute(f"SELECT ... '{user_param}'")`
  - `SEC-PY-004` (High): Hardcoded secret in `API_SECRET_KEY`
  - `SEC-PY-004` (High): Hardcoded secret in `DB_PASS`
  - `SEC-PY-005` (Critical): Insecure deserialization via `pickle.loads(untrusted_stream)`
  - `SEC-PY-006` (Medium): Weak cryptographic hash via `hashlib.md5()`

### Source Code
```python
import os
import subprocess
import pickle
import hashlib
import sqlite3

# VULNERABILITY: Hardcoded API credentials
API_SECRET_KEY = "AIzaSyD-untrusted-production-key-999"
DB_PASS = "SuperSecretPassword123!"

def process_user_query(user_param: str):
    # VULNERABILITY: Arbitrary code execution via eval()
    evaluated = eval(user_param)
    
    # VULNERABILITY: OS Command Injection via shell=True
    subprocess.Popen("ping -c 1 " + user_param, shell=True)
    
    # VULNERABILITY: SQL Injection via unescaped string formatting
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM accounts WHERE username = '{user_param}'")
    
    return evaluated

def deserialize_state(untrusted_stream):
    # VULNERABILITY: Insecure Deserialization via pickle
    return pickle.loads(untrusted_stream)

def hash_user_password(password: str) -> str:
    # VULNERABILITY: Weak broken cryptographic hash (MD5)
    return hashlib.md5(password.encode()).hexdigest()
```

---

## Scenario 4: Valid Java (Secure Banking Transfer)
- **Target File**: `SecureBankTransfer.java`
- **Language**: Java
- **UI Dropdown**: `✅ Valid Java (Secure Code)`
- **Expected Validation Result**: `valid_syntax: true` (`javac` compilation succeeded)
- **Expected Findings Count**: `0`

### Source Code
```java
import java.math.BigDecimal;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

public class SecureBankTransfer {
    private final String accountId;
    private BigDecimal balance;

    public SecureBankTransfer(String accountId, BigDecimal initialBalance) {
        this.accountId = accountId;
        this.balance = initialBalance;
    }

    public synchronized void transfer(BigDecimal amount) {
        if (amount.compareTo(BigDecimal.ZERO) > 0 && this.balance.compareTo(amount) >= 0) {
            this.balance = this.balance.subtract(amount);
            System.out.println("Transfer successful. New balance: " + this.balance);
        } else {
            System.out.println("Insufficient funds or invalid transfer amount.");
        }
    }

    public static byte[] hashAuditTrail(String auditData) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(auditData.getBytes(StandardCharsets.UTF_8));
    }

    public static void main(String[] args) throws Exception {
        SecureBankTransfer account = new SecureBankTransfer("ACC-10492", new BigDecimal("1500.00"));
        account.transfer(new BigDecimal("250.00"));
    }
}
```

---

## Scenario 5: Compilation-Broken Java
- **Target File**: `BrokenCompilerDemo.java`
- **Language**: Java
- **UI Action**: Paste into editor and click **🔍 Validate Syntax**
- **Expected Validation Result**: `valid_syntax: false`
- **Expected Diagnostics**: Genuine OpenJDK `javac` compiler errors reporting missing semicolons and unclosed string literals with exact line and column coordinates.

### Source Code
```java
public class BrokenCompilerDemo {
    public static void main(String[] args) {
        int balance = 100
        System.out.println("Unclosed string literal);
    }
}
```

---

## Scenario 6: Vulnerable Java (Multi-Flaw Inspection)
- **Target File**: `LegacyPortalService.java`
- **Language**: Java
- **UI Dropdown**: `⚠️ Vulnerable Java (OWASP Flaws)`
- **Expected Validation Result**: `valid_syntax: true`
- **Expected Findings Count**: `6`
  - `SEC-JV-001` (Critical): SQL Injection via unparameterized concatenation
  - `SEC-JV-002` (Critical): OS Command Injection via `Runtime.getRuntime().exec`
  - `SEC-JV-003` (High): Hardcoded secret in `AWS_SECRET`
  - `SEC-JV-003` (High): Hardcoded secret in `DB_PASSWORD`
  - `SEC-JV-004` (High): Insecure deserialization via `ObjectInputStream.readObject()`
  - `SEC-JV-005` (Medium): Weak broken cryptographic hash via `MessageDigest.getInstance("MD5")`

### Source Code
```java
import java.io.*;
import java.sql.*;
import java.security.MessageDigest;

public class LegacyPortalService {
    // VULNERABILITY: Hardcoded sensitive credentials
    private static final String AWS_SECRET = "AKIAIOSFODNN7EXAMPLE_SECRET_KEY";
    private static final String DB_PASSWORD = "RootAdminPassword_2026";

    public void authenticateUser(Connection conn, String user, String pass) throws Exception {
        Statement stmt = conn.createStatement();
        // VULNERABILITY: SQL Injection via direct concatenation
        String query = "SELECT * FROM users WHERE username = '" + user + "' AND password = '" + pass + "'";
        ResultSet rs = stmt.executeQuery(query);
    }

    public void executeSystemMaintenance(String scriptName) throws Exception {
        // VULNERABILITY: OS Command Injection via Runtime.getRuntime().exec()
        Runtime.getRuntime().exec("sh /opt/scripts/" + scriptName);
    }

    public Object restoreSession(InputStream rawInput) throws Exception {
        // VULNERABILITY: Insecure Deserialization via ObjectInputStream
        ObjectInputStream ois = new ObjectInputStream(rawInput);
        return ois.readObject();
    }

    public String computeLegacyHash(String data) throws Exception {
        // VULNERABILITY: Broken cryptographic hash (MD5)
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(data.getBytes());
        return new String(md.digest());
    }
}
```
