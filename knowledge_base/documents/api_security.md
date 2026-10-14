# OWASP API Security Best Practices Cheat Sheet

Source: https://owasp.org/www-project-api-security/
Retrieved: 2026-10-12
Author: OWASP API Security Project Team
Topic: API Security & Hardening

## Introduction
Modern application architectures rely heavily on REST, GraphQL, and RPC APIs. APIs frequently expose underlying business objects, database schemas, and microservice communication channels, making them primary targets for attackers.

## Key API Vulnerabilities (OWASP API Top 10 Highlights)
1. **Broken Object Level Authorization (BOLA / API1):** Endpoints that accept user IDs or entity keys without validating that the authenticated client has permission to access that specific object.
2. **Broken Authentication (API2):** Weak token handling, missing rate limiting on credential endpoints, or accepting unvalidated JWT signatures (`alg: "none"`).
3. **Broken Object Property Level Authorization (API3 / Mass Assignment):** Binding client JSON payloads directly into database models without filtering allowed fields, allowing callers to overwrite properties such as `is_admin`, `verified`, or `account_balance`.
4. **Unrestricted Resource Consumption (API4):** Missing rate limiting or lack of maximum page size (`limit`/`offset`) controls, leading to API Denial of Service.

## Prevention and Defense Patterns

### 1. Strict Request Schema Validation & Explicit DTOs
Never map raw request dictionaries directly to internal database entity classes. Use strictly typed Data Transfer Objects (DTOs) or Pydantic models with extra fields forbidden.

### Secure Python Pattern (FastAPI / Pydantic)
```python
from pydantic import BaseModel, Field, EmailStr

class UserProfileUpdateRequest(BaseModel):
    # Only expose attributes users are authorized to update
    full_name: str = Field(..., max_length=100)
    email: EmailStr

    class Config:
        extra = "forbid"  # Reject unexpected or privileged keys like is_admin

@app.put("/api/users/me")
def update_profile(data: UserProfileUpdateRequest, user: CurrentUser):
    user.full_name = data.full_name
    user.email = data.email
    db.session.commit()
    return {"status": "updated"}
```

### 2. Implement Tiered Rate Limiting
Apply global and per-endpoint rate limits (especially on authentication and resource-intensive endpoints):
- Return standard HTTP `429 Too Many Requests` responses with `Retry-After` headers.
- Monitor repeated authorization failure spikes per IP or API key.

## Practical Inspection & Remediation Checklist
- Audit all PUT/POST endpoints to ensure object mapping filters forbidden fields.
- Validate that all public endpoints require token authentication unless specifically whitelisted as public (e.g. `/health`).
