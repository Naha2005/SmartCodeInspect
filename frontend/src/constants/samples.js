export const SAMPLE_CODES = {
  python_valid: {
    filename: "secure_calculator.py",
    language: "python",
    complexity: "low",
    title: "🟢 Low: Secure Calculator (Clean & Valid)",
    code: `import math
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
`
  },

  python_moderate: {
    filename: "data_pipeline_service.py",
    language: "python",
    complexity: "moderate",
    title: "🟡 Moderate: Data Pipeline (Quality Smells & Resource Flaws)",
    code: `import json
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# Quality: Mutable default argument anti-pattern
def process_pipeline_batch(records: List[Dict[str, Any]], error_log=[]):
    """Processes batch ETL records with maintainability smells."""
    # Quality: Print statement left in production code
    print(f"Starting batch of {len(records)} items")
    
    # Quality: Resource leak / unmanaged file descriptor without with-context
    metrics_file = open("pipeline.log", "a")
    metrics_file.write(f"Processed: {len(records)}\\n")
    
    results = []
    # Quality: High cyclomatic complexity & deeply nested branches
    for item in records:
        if item.get("status") == "ACTIVE":
            if item.get("tier") == "ENTERPRISE":
                if item.get("score", 0) > 80:
                    results.append({"id": item.get("id"), "action": "EXPEDITE"})
                else:
                    results.append({"id": item.get("id"), "action": "STANDARD"})
            elif item.get("tier") == "PREMIUM":
                results.append({"id": item.get("id"), "action": "STANDARD"})
            else:
                results.append({"id": item.get("id"), "action": "BATCH"})
        else:
            # Quality: Silenced error / overly broad exception handler
            try:
                error_log.append(f"Skipping {item.get('id')}")
            except Exception:
                pass
                
    metrics_file.close()
    return results
`
  },

  python_vulnerable: {
    filename: "vulnerable_service.py",
    language: "python",
    complexity: "high",
    title: "🔴 High: Vulnerable Service (OWASP Flaws & Quality Defects)",
    code: `import os
import subprocess
import pickle
import hashlib
import sqlite3
import requests
from math import *

# Security: Hardcoded API credentials
API_SECRET_KEY = "AIzaSyD-untrusted-production-key-999"
DB_PASS = "SuperSecretPassword123!"

# Quality: Mutable default argument anti-pattern
def process_user_query(user_param: str, context_cache=[]):
    # Quality: Print statement left in production code
    print("Processing user query:", user_param)
    
    # Vulnerability: Arbitrary code execution via eval()
    evaluated = eval(user_param)
    
    # Vulnerability: OS Command Injection via shell=True
    subprocess.Popen("ping -c 1 " + user_param, shell=True)
    
    # Vulnerability: SQL Injection via unescaped string formatting
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM accounts WHERE username = '{user_param}'")
    
    # Vulnerability: Path Traversal
    file_target = os.path.join("/var/uploads", user_param)
    
    # Quality: Resource leak / unmanaged file open
    f = open("audit.log", "r")
    
    # Quality: Empty exception handler / silenced error
    try:
        if len(user_param) > 0 and user_param != "admin" and not user_param.startswith("sys"):
            pass
    except Exception:
        pass
        
    return evaluated

def deserialize_state(untrusted_stream):
    # Vulnerability: Insecure Deserialization via pickle
    return pickle.loads(untrusted_stream)

def hash_user_password(password: str) -> str:
    # Vulnerability: Weak broken cryptographic hash (MD5)
    return hashlib.md5(password.encode()).hexdigest()
`
  },

  java_valid: {
    filename: "SecureBankTransfer.java",
    language: "java",
    complexity: "low",
    title: "🟢 Low: Secure Banking (Clean & Valid)",
    code: `import java.math.BigDecimal;
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
        if (amount != null && amount.compareTo(BigDecimal.ZERO) > 0 && this.balance.compareTo(amount) >= 0) {
            this.balance = this.balance.subtract(amount);
        }
    }

    public static byte[] hashAuditTrail(String auditData) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(auditData.getBytes(StandardCharsets.UTF_8));
    }
}
`
  },

  java_moderate: {
    filename: "OrderNotificationManager.java",
    language: "java",
    complexity: "moderate",
    title: "🟡 Moderate: Order Manager (Quality Smells & Resource Flaws)",
    code: `import java.util.*;
import java.io.*;

public class OrderNotificationManager {

    // Quality: Long parameter list smell (excessive parameters)
    public void dispatchOrderAlert(
        long orderId,
        String customerEmail,
        String customerPhone,
        double orderTotal,
        int priorityTier,
        boolean isExpressShipping,
        String destinationRegion
    ) {
        // Quality: Console output left in production code
        System.out.println("Dispatching notification for order ID: " + orderId);

        // Quality: Deeply nested conditional logic / high complexity
        if (customerEmail != null && !customerEmail.trim().isEmpty()) {
            if (priorityTier > 3) {
                if (isExpressShipping) {
                    if (orderTotal > 1000.0) {
                        scheduleEmail(customerEmail, "URGENT_HIGH_VALUE");
                    } else {
                        scheduleEmail(customerEmail, "URGENT_STANDARD");
                    }
                } else {
                    scheduleEmail(customerEmail, "STANDARD");
                }
            }
        }

        // Quality: Empty catch block / swallowed exception
        try {
            validateRegionRouting(destinationRegion);
        } catch (Exception e) {
            // Silently swallowed without logging
        }
    }

    private void scheduleEmail(String email, String template) {
        // Safe internal scheduling stub
    }

    private void validateRegionRouting(String region) throws Exception {
        if (region == null || region.isEmpty()) {
            throw new IllegalArgumentException("Invalid region");
        }
    }
}
`
  },

  java_vulnerable: {
    filename: "LegacyPortalService.java",
    language: "java",
    complexity: "high",
    title: "🔴 High: Legacy Portal (OWASP Flaws & Quality Defects)",
    code: `import java.io.*;
import java.sql.*;
import java.security.MessageDigest;
import java.util.*;
import javax.xml.parsers.DocumentBuilderFactory;

public class LegacyPortalService {
    // Security: Hardcoded sensitive credentials
    private static final String AWS_SECRET = "AKIAIOSFODNN7EXAMPLE_SECRET_KEY";
    private static final String DB_PASSWORD = "RootAdminPassword_2026";

    // Quality: Long parameter list smell
    public void authenticateUser(Connection conn, String user, String pass, String token, String role, String ip) throws Exception {
        Statement stmt = conn.createStatement();
        // Vulnerability: SQL Injection via direct concatenation
        String query = "SELECT * FROM users WHERE username = '" + user + "' AND password = '" + pass + "'";
        ResultSet rs = stmt.executeQuery(query);
    }

    public void executeSystemMaintenance(String scriptName) throws Exception {
        // Quality: Console output in production
        System.out.println("Executing system maintenance: " + scriptName);
        
        // Vulnerability: OS Command Injection via Runtime.getRuntime().exec()
        Runtime.getRuntime().exec("sh /opt/scripts/" + scriptName);
        
        // Vulnerability: Path Traversal in File constructor
        File scriptFile = new File("/opt/scripts", scriptName);
    }

    public Object restoreSession(InputStream rawInput) throws Exception {
        // Vulnerability: Insecure Deserialization via ObjectInputStream
        ObjectInputStream ois = new ObjectInputStream(rawInput);
        
        // Quality: Empty catch block
        try {
            return ois.readObject();
        } catch (Exception e) {
        }
        return null;
    }

    // Quality: Method name starting with uppercase
    public String ComputeLegacyHash(String data) throws Exception {
        // Vulnerability: Broken cryptographic hash (MD5)
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(data.getBytes());
        return new String(md.digest());
    }
}
`
  }
};
