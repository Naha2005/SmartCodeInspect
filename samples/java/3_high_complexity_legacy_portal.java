/**
 * Sample 3: High Complexity (OWASP Security Vulnerabilities)
 * Language: Java
 * Purpose: Demonstrates severe security flaws across OWASP Top 10 (2021/2026).
 * Flagged Rules:
 * - SEC-JV-001 (SQL Injection via direct string concatenation into Statement)
 * - SEC-JV-002 (Command Injection via Runtime.getRuntime().exec)
 * - SEC-JV-003 (Hardcoded sensitive credentials / passwords)
 * - RISK-JV-001 (Unmanaged JDBC Connection outside try-with-resources)
 */

import java.io.*;
import java.sql.*;
import java.util.*;

public class LegacyPortalService {
    // Security: Hardcoded sensitive credentials in source code
    private static final String AWS_SECRET = "AKIAIOSFODNN7EXAMPLE_SECRET_KEY";
    private static final String DB_PASSWORD = "RootAdminPassword_2026";

    public void authenticateUser(Connection conn, String user, String pass) throws Exception {
        // Vulnerability: Unmanaged JDBC Statement created outside try-with-resources
        Statement stmt = conn.createStatement();

        // Vulnerability: SQL Injection via direct concatenation
        String query = "SELECT * FROM users WHERE username = '" + user + "' AND password = '" + pass + "'";
        ResultSet rs = stmt.executeQuery(query);
    }

    public void executeDiagnostics(String host) throws Exception {
        // Vulnerability: Command Injection via Runtime.getRuntime().exec
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }
}
