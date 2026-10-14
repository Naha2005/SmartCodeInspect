# OWASP SQL Injection Prevention Cheat Sheet

Source: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
Retrieved: 2026-10-11
Author: OWASP Cheat Sheet Series Team

## Introduction
SQL Injection (SQLi) is an injection attack wherein an attacker executes malicious SQL statements that control a database server behind a web application. Attackers use SQL injection vulnerabilities to bypass application security measures, authenticate as an administrator, access, modify, or delete sensitive data, and in some cases execute operating system commands.

## Primary Defense: Use Parameterized Queries (Prepared Statements)
Prepared statements ensure that an attacker cannot change the intent of a query, even if SQL commands are inserted by an untrusted source. When an application uses a prepared statement, the database compiles the SQL statement template first, and then binds user input parameters safely to the execution plan without interpreting user data as executable SQL commands.

### Java Implementation
In Java, use `PreparedStatement` with bind variables:
```java
String selectUserQuery = "SELECT id, username, email FROM users WHERE username = ? AND status = ?";
PreparedStatement pstmt = connection.prepareStatement(selectUserQuery);
pstmt.setString(1, userSuppliedUsername);
pstmt.setString(2, "ACTIVE");
ResultSet results = pstmt.executeQuery();
```
Never concatenate strings or user variables directly into the query string passed to `connection.prepareStatement()` or `statement.executeQuery()`.

### Python Implementation
In Python DB-API compliant drivers (e.g., sqlite3, psycopg2, mysql-connector):
```python
# SAFE: parameterized query with placeholder tuple
cursor.execute("SELECT id, username FROM users WHERE username = %s AND status = %s", (username, status))
```
Never use f-strings, `%` formatting, or string concatenation:
```python
# VULNERABLE:
cursor.execute(f"SELECT * FROM users WHERE username = '{username}'") # SQL Injection!
```

## Secondary Defense: Stored Procedures
Stored procedures can protect against SQL injection when implemented safely. The stored procedure itself must parameterize arguments internally rather than generating dynamic SQL strings with concatenation inside the procedure.

## Defense: Allow-list Input Validation
When parameterization is impossible—such as when table names, column names, or sort orders (ASC/DESC) must be chosen dynamically—use a strict allow-list of authorized identifiers. Reject any input that does not match an exact known safe constant.
