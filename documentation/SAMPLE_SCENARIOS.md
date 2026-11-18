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
  - `SEC-PY-002` (Critical): OS Command Injection via `subprocess.call(cmd, shell=True)`
  - `SEC-PY-003` (Critical): SQL Injection via raw f-string query formatting
  - `SEC-PY-004` (High): Hardcoded database credential string (`SECRET_KEY_DB`)
  - `SEC-PY-005` (High): Insecure deserialization via `pickle.loads(raw_token)`
  - `SEC-PY-006` (Medium): Weak hash algorithm via `hashlib.md5(data)`
  - `PRACTICE-PY-002` (Medium): Unclosed file handle without context manager

### Source Code
```python
import os
import sqlite3
import subprocess
import hashlib
import pickle

DB_PASSWORD = "HardcodedSuperSecret2026!#"

def run_user_code(user_param):
    # VULNERABILITY: Arbitrary code execution via eval
    return eval(user_param)

def execute_system_command(target_host):
    # VULNERABILITY: OS Command Injection via shell=True
    cmd = f"ping -c 1 {target_host}"
    return subprocess.call(cmd, shell=True)

def search_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # VULNERABILITY: SQL Injection via unparameterized f-string
    query = f"SELECT * FROM accounts WHERE user = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()

def load_session_payload(serialized_bytes):
    # VULNERABILITY: Insecure Deserialization via pickle
    return pickle.loads(serialized_bytes)

def generate_checksum(data):
    # VULNERABILITY: Cryptographically broken MD5 hash
    return hashlib.md5(data.encode()).hexdigest()

def read_log_unclosed(filepath):
    # CODE SMELL: Unmanaged file handle without with-context
    f = open(filepath, "r")
    content = f.read()
    return content
```

---

## Scenario 4: Valid Java (Thread-Safe Bank Ledger)
- **Target File**: `SecureBankTransfer.java`
- **Language**: Java
- **UI Dropdown**: `✅ Valid Java (Secure Code)`
- **Expected Validation Result**: `valid_syntax: true`
- **Expected Findings Count**: `0`

### Source Code
```java
import java.math.BigDecimal;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

public class SecureBankTransfer {
    private final String accountId;
    private BigDecimal balance;
    private final ReentrantLock lock = new ReentrantLock();

    public SecureBankTransfer(String accountId, BigDecimal initialBalance) {
        this.accountId = Objects.requireNonNull(accountId, "Account ID cannot be null");
        this.balance = Objects.requireNonNull(initialBalance, "Initial balance cannot be null");
    }

    public boolean transferFunds(SecureBankTransfer target, BigDecimal amount) {
        if (amount.compareTo(BigDecimal.ZERO) <= 0) {
            throw new IllegalArgumentException("Transfer amount must be strictly positive");
        }
        lock.lock();
        try {
            if (this.balance.compareTo(amount) >= 0) {
                this.balance = this.balance.subtract(amount);
                target.deposit(amount);
                return true;
            }
            return false;
        } finally {
            lock.unlock();
        }
    }

    public void deposit(BigDecimal amount) {
        lock.lock();
        try {
            this.balance = this.balance.add(amount);
        } finally {
            lock.unlock();
        }
    }

    public BigDecimal getBalance() {
        lock.lock();
        try {
            return this.balance;
        } finally {
            lock.unlock();
        }
    }
}
```

---

## Scenario 5: Compiler-Broken Java
- **Target File**: `BrokenCompilerDemo.java`
- **Language**: Java
- **UI Action**: Paste into editor and click **🔍 Validate Syntax**
- **Expected Validation Result**: `valid_syntax: false`
- **Expected Diagnostics**: 3 discrete javac errors (`';' expected`, `cannot find symbol: variable missingSymbol`, `reached end of file while parsing`).

### Source Code
```java
public class BrokenCompilerDemo {
    public void brokenMethod() {
        int x = 100 // missing semicolon
        missingSymbol = x + 5;
    }
```

---

## Scenario 6: Vulnerable Java (OWASP Exploit Suite)
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

---

## 📁 Standalone 3-Tier Code Samples Directory

For convenient offline review, drag-and-drop testing, and file-upload inspection, the repository includes ready-to-test standalone files in the `samples/` directory:

```text
samples/
├── python/
│   ├── 1_low_complexity_secure_calculator.py     (🟢 Low: Clean math engine, 100/100)
│   ├── 2_moderate_complexity_pipeline.py         (🟡 Moderate: Data pipeline with code smells)
│   └── 3_high_complexity_vulnerable_service.py    (🔴 High: OWASP exploits, SQLi, RCE, Deserialization)
└── java/
    ├── 1_low_complexity_secure_transfer.java     (🟢 Low: Thread-safe banking logic, 100/100)
    ├── 2_moderate_complexity_order_manager.java  (🟡 Moderate: Order manager with anti-patterns)
    └── 3_high_complexity_legacy_portal.java      (🔴 High: OWASP exploits, SQLi, exec, hardcoded keys)
```

Each sample can be directly uploaded via the **📁 Upload Source** button or dragged & dropped into the Code Editor for automatic language detection and scanning.
