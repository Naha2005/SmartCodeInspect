# OWASP SQL Injection Prevention Cheat Sheet (2026 Edition)

Source: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
Retrieved: 2026-10-25
Author: OWASP Cheat Sheet Series Global Security Committee
Status: Active Standard (2026 Revision)

## 1. Introduction and Threat Landscape
SQL Injection (SQLi) represents one of the oldest yet most damaging vulnerabilities in software engineering, classified under CWE-89 (Improper Neutralization of Special Elements used in an SQL Command) and OWASP Top 10 category A03:2026 – Injection.

SQL injection occurs whenever untrusted data is concatenated or interpolated directly into an SQL command string without prior parameterization. This allows malicious actors to alter the syntax, structure, and semantic intent of the database query. Consequences of successful SQL injection range from unauthorized disclosure of sensitive data, authentication bypass, and silent record alteration to arbitrary command execution on the database host operating system and complete database takeover.

---

## 2. Classification of SQL Injection Attacks

### 2.1 In-Band SQLi (Classic)
The attacker uses the same communication channel to launch the attack and gather results.
- **Error-Based SQLi**: Inducing verbose database errors containing database version, table names, or data contents.
- **UNION-Based SQLi**: Using the `UNION` or `UNION ALL` operator to append arbitrary result sets to the original query output.

### 2.2 Inferential SQLi (Blind)
The application does not transfer data directly in HTTP responses or display database errors. The attacker reconstructs data by asking true/false questions:
- **Boolean-Based Blind SQLi**: Discerning truth by observing subtle changes in HTTP response content, status codes, or page sizes.
- **Time-Based Blind SQLi**: Injecting deliberate sleep functions (e.g. `pg_sleep(5)`, `WAITFOR DELAY '0:0:5'`) to infer boolean truth from server latency.

### 2.3 Out-of-Band SQLi
Used when the attacker cannot observe results directly and the server is too unstable for time-based attacks. Relies on the database server generating outbound DNS or HTTP requests (e.g. `xp_dirtree` or `UTL_HTTP`).

### 2.4 Second-Order SQLi
Hostile input is safely stored in the database initially without immediate execution, but is later pulled and concatenated into an unsafe dynamic query in another background job or downstream API flow.

---

## 3. Primary Defensive Control: Parameterized Queries (Prepared Statements)

Parameterized queries (also known as Prepared Statements) are the definitive, infallible defense against SQL injection. When prepared statements are utilized:
1. The database compiles the SQL statement template into an immutable execution plan *before* inserting parameter values.
2. Parameter values are treated strictly as literal data, never as executable SQL syntax.
3. Quotation marks, SQL metacharacters (`;`, `--`, `/*`), or boolean keywords (`OR 1=1`) inside parameters cannot break out of data boundaries.

---

## 4. Python SQL Injection Prevention

### 4.1 Vulnerable vs Secure Patterns in Python (sqlite3 & psycopg2)

#### Vulnerable Pattern (Direct String Concatenation)
```python
# VULNERABLE: Direct string formatting into SQL query
import sqlite3

def query_user_account(user_input):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # SQL INJECTION (CWE-89): Attacker inputs: ' OR '1'='1
    query = f"SELECT id, username, email FROM users WHERE username = '{user_input}'"
    cursor.execute(query)
    return cursor.fetchall()
```

#### Secure Pattern (Parameterized Prepared Query)
```python
# SECURE: Using parameterized placeholders
import sqlite3

def query_user_account_secure(user_input: str):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # Safe: Question mark placeholder treats input as pure literal data
    query = "SELECT id, username, email FROM users WHERE username = ?"
    cursor.execute(query, (user_input,))
    return cursor.fetchall()
```

### 4.2 PostgreSQL with psycopg3 / psycopg2

#### Secure Pattern
```python
import psycopg

def get_orders_by_customer(customer_id: int, status: str):
    with psycopg.connect("dbname=shop user=app") as conn:
        with conn.cursor() as cur:
            # Psycopg uses %s placeholders for parameterization (NOT Python string formatting)
            cur.execute(
                "SELECT order_id, total, created_at FROM orders WHERE customer_id = %s AND status = %s",
                (customer_id, status)
            )
            return cur.fetchall()
```

### 4.3 SQLAlchemy ORM Secure Practices

#### Vulnerable SQLAlchemy Pattern
```python
# VULNERABLE: Using raw text() with string interpolation
from sqlalchemy import text
from sqlalchemy.orm import Session

def get_products(session: Session, category: str):
    # DANGEROUS: text() with f-string breaks ORM protections
    stmt = text(f"SELECT * FROM products WHERE category = '{category}'")
    return session.execute(stmt).fetchall()
```

#### Secure SQLAlchemy Pattern
```python
# SECURE: Using bound parameters with text() or ORM query expressions
from sqlalchemy import text, select
from sqlalchemy.orm import Session
from models import Product

def get_products_secure(session: Session, category: str):
    # Method A: Bound parameters in raw text
    stmt = text("SELECT * FROM products WHERE category = :cat")
    results = session.execute(stmt, {"cat": category}).fetchall()

    # Method B: Idiomatic ORM filter (strongly recommended)
    orm_stmt = select(Product).where(Product.category == category)
    return session.scalars(orm_stmt).all()
```

---

## 5. Java SQL Injection Prevention

### 5.1 Vulnerable vs Secure Patterns in Java (JDBC)

#### Vulnerable Pattern (Concatenation in Statement)
```java
// VULNERABLE: Direct concatenation into executeQuery
import java.sql.Connection;
import java.sql.Statement;
import java.sql.ResultSet;

public class LegacyAccountService {
    public void findAccount(Connection conn, String accountId) throws Exception {
        Statement stmt = conn.createStatement();
        // SQL Injection: accountId = "1001' OR '1'='1"
        String sql = "SELECT id, balance FROM accounts WHERE id = '" + accountId + "'";
        ResultSet rs = stmt.executeQuery(sql);
        while (rs.next()) {
            System.out.println("Balance: " + rs.getDouble("balance"));
        }
    }
}
```

#### Secure Pattern (PreparedStatement with Typed Setters)
```java
// SECURE: Java PreparedStatement with parameterized placeholders
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class SecureAccountService {
    public void findAccount(Connection conn, String accountId) throws Exception {
        String sql = "SELECT id, balance FROM accounts WHERE id = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            // Strongly typed parameter binding
            pstmt.setString(1, accountId);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    System.out.println("Balance: " + rs.getDouble("balance"));
                }
            }
        }
    }
}
```

### 5.2 Hibernate / JPA Secure Querying

#### Vulnerable HQL / JPQL
```java
// VULNERABLE: Concatenation inside HQL query string
String hql = "FROM Customer c WHERE c.lastName = '" + lastName + "'";
Query query = session.createQuery(hql, Customer.class);
```

#### Secure HQL / JPQL
```java
// SECURE: Named parameter binding in HQL
String hql = "FROM Customer c WHERE c.lastName = :lName";
TypedQuery<Customer> query = em.createQuery(hql, Customer.class);
query.setParameter("lName", lastName);
List<Customer> customers = query.getResultList();
```

---

## 6. Dynamic SQL Identifiers (Table & Column Names)

Parameters cannot be used for SQL structural identifiers, such as table names, column names, or sort order (`ASC` / `DESC`). When dynamic identifier construction is unavoidable, developers must apply **strict allowlisting**.

### Secure Dynamic Sorting in Python
```python
ALLOWED_SORT_COLUMNS = {
    "price": "price",
    "created_at": "created_at",
    "name": "name"
}

ALLOWED_SORT_DIRECTIONS = {
    "asc": "ASC",
    "desc": "DESC"
}

def fetch_sorted_items(user_sort_col: str, user_direction: str):
    # Enforce strict allowlist matching
    col = ALLOWED_SORT_COLUMNS.get(user_sort_col.lower())
    direction = ALLOWED_SORT_DIRECTIONS.get(user_direction.lower())

    if not col or not direction:
        raise ValueError("Invalid sorting parameter supplied.")

    # Safe to interpolate verified identifier constants
    query = f"SELECT id, name, price FROM items ORDER BY {col} {direction}"
    cursor.execute(query)
    return cursor.fetchall()
```

---

## 7. Stored Procedures and Defense-in-Depth

### 7.1 Stored Procedure Caveats
Stored procedures are only safe if the procedure itself uses parameterized queries. If a stored procedure builds a query using dynamic concatenation (e.g. `sp_executesql 'SELECT * FROM users WHERE name = ''' + @user + ''''`), it remains acutely vulnerable to SQL injection.

### 7.2 Database Account Least Privilege
- Applications should connect using database roles granted the bare minimum permissions required.
- Do not connect as `sa`, `postgres`, or `root`.
- Administrative operations (`DROP TABLE`, `CREATE DATABASE`, `ALTER`) must be restricted to migration scripts running under dedicated deployment accounts.
- Restrict read access to sensitive system tables (`pg_catalog`, `information_schema`, `sys.tables`).

---

## 8. Common SQL Injection Bypasses and Edge Cases

1. **Obfuscation & Encoding**: Attackers use URL encoding (`%27`), double encoding (`%2527`), Unicode normalization, or comments (`/**/`) to evade weak regex filters. Regex filtering is never an acceptable alternative to parameterization.
2. **Numeric Fields**: Forgetting to parameterize integer fields (`WHERE id = " + id`) is a common mistake. Even numeric parameters must be bound or strictly cast to integers.
3. **Truncation Attacks**: In systems with fixed column limits, trailing payload fragments may be truncated, altering the trailing quote behavior.
4. **LIKE Clause Injection**: When using `LIKE ?`, characters like `%` and `_` inside parameter values behave as wildcards unless escaped (`\_` and `\%`) with an explicit `ESCAPE` clause.

---

## 9. Second-Order SQL Injection (Deep Dive)

Second-order SQL injection (also termed stored SQL injection) occurs when hostile input is initially stored safely in the database, but is subsequently retrieved and concatenated into an unsafe SQL statement executed by a secondary process, reporting job, or administrative dashboard.

### 9.1 Vulnerable Second-Order Scenario (Python)
```python
# STEP 1: Attacker registers an account with payload: admin'--
def register_account(username, password):
    # Parameterized: Safely stored in accounts table without exploit execution
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()

# STEP 2: Later, an administrative maintenance task queries profile data unsafely
def rebuild_user_statistics():
    cursor.execute("SELECT username FROM users")
    usernames = [row[0] for row in cursor.fetchall()]

    for user in usernames:
        # VULNERABLE: Re-interpolating stored data into dynamic query
        # When user is "admin'--", the query becomes:
        # UPDATE user_metrics SET last_audit = datetime('now') WHERE username = 'admin'--'
        cursor.execute(f"UPDATE user_metrics SET last_audit = datetime('now') WHERE username = '{user}'")
```

### 9.2 Remediation for Second-Order SQLi
Data retrieved from your own database must never be treated as inherently trusted. All queries—regardless of whether input comes from an HTTP request, message queue, or internal database table—must use parameterized prepared statements without exception:
```python
# SECURE: Always parameterize queries even when querying internal database records
cursor.execute("UPDATE user_metrics SET last_audit = datetime('now') WHERE username = ?", (user,))
```

---

## 10. NoSQL Injection Defense (MongoDB & Document Stores)

Modern applications frequently use NoSQL document stores (such as MongoDB, CouchDB, or DocumentDB). While traditional relational SQL syntax does not apply, NoSQL systems are vulnerable to query operator injection (CWE-943).

### 10.1 Vulnerable NoSQL Pattern (Python / PyMongo)
```python
# VULNERABLE: Direct dictionary query accepting raw client JSON
from flask import request
import pymongo

@app.route("/api/login", methods=["POST"])
def nosql_login():
    payload = request.get_json()
    # Attacker sends: {"username": "admin", "password": {"$ne": ""}}
    # Because password is not an empty string, the query evaluates to TRUE!
    user = db.users.find_one({
        "username": payload["username"],
        "password": payload["password"]
    })
    if user:
        return {"status": "authenticated", "role": user["role"]}
    return {"status": "unauthorized"}, 401
```

### 10.2 Secure NoSQL Pattern (Strict Type Coercion & Schema Validation)
```python
# SECURE: Enforcing strict string types and rejecting operator dictionaries
@app.route("/api/login", methods=["POST"])
def nosql_login_secure():
    payload = request.get_json() or {}
    raw_user = payload.get("username")
    raw_pass = payload.get("password")

    # Reject non-string inputs (blocks {"$ne": ...} operator injections)
    if not isinstance(raw_user, str) or not isinstance(raw_pass, str):
        return {"error": "Invalid credential payload format"}, 400

    # Retrieve user by username only, then verify password using Argon2id
    user = db.users.find_one({"username": raw_user})
    if not user or not password_service.verify(user["password_hash"], raw_pass):
        return {"status": "unauthorized"}, 401

    return {"status": "authenticated", "role": user.get("role", "user")}
```

---

## 11. Testing and Verification Methodologies

### 11.1 Static Analysis (SAST) Rule Auditing
- Verify that SAST analyzers (such as SmartCodeInspect rules `SEC-PY-003` and `SEC-JV-001`) flag every dynamic string concatenation inside query methods.
- Prohibit suppressions unless signed off by a lead security architect.

### 11.2 Automated Dynamic Testing (DAST)
- Run automated penetration tests using tools such as OWASP ZAP or sqlmap against staging environments.
- Verify that single quotes (`'`), double quotes (`"`), backslashes (`\`), SQL comment markers (`--`), and arithmetic subqueries (`SLEEP(5)`) do not produce differential status codes or timing anomalies.

---

## 12. Comprehensive SQL Injection Prevention Checklist

- [ ] Every database interaction utilizes parameterized prepared statements or safe ORM mappings.
- [ ] Zero dynamic string formatting (f-strings, `+` operators, `str.format()`) used to build SQL query text.
- [ ] Table names, column names, and sort directions validated against strict in-memory allowlists.
- [ ] Database users operate under the Principle of Least Privilege with restricted permissions.
- [ ] Detailed database error messages suppressed from production user interfaces.
- [ ] ORM raw query methods (`text()`, `raw()`, `nativeQuery()`) inspected for accidental string concatenation.
- [ ] Stored procedures verified to ensure no internal dynamic SQL concatenation is executed.
- [ ] Automated static analysis (SAST) rules `SEC-PY-003` and `SEC-JV-001` enforced in CI/CD pipelines.
- [ ] NoSQL queries strictly validate scalar types to prevent query operator injection (`$ne`, `$gt`, `$where`).
- [ ] Second-order database queries apply parameterized binding even when processing internal records.

