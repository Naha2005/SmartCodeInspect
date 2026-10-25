# OWASP Broken Access Control Prevention Cheat Sheet

Source: https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html
Retrieved: 2026-10-12
Author: OWASP Cheat Sheet Series Team
Topic: Broken Access Control & Authorization

## Introduction
Access control (or authorization) enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, destruction of data, or performing a business function outside the user's limits.

## Common Vulnerabilities and Attack Scenarios
1. **Insecure Direct Object References (IDOR):** An application uses user-supplied input to access objects directly without verifying ownership or authorization (e.g., `/api/user/account?id=1052`).
2. **Missing Function Level Access Control:** Administrative endpoints or privileged functions are exposed to unauthenticated users or standard users simply by hiding UI links without enforcing server-side authorization.
3. **Bypassing Access Control Checks:** Tampering with JSON Web Tokens (JWTs), cookies, hidden form fields, or manipulating URLs to impersonate other identities.
4. **CORS Misconfiguration:** Permitting untrusted origins unauthorized access to protected API endpoints via overly permissive `Access-Control-Allow-Origin: *` headers with credentials.

## Prevention and Defense Methods
- **Enforce Least Privilege by Default:** Deny access by default unless a resource is explicitly made public.
- **Implement Server-Side Access Control Checks:** Never rely solely on client-side role checks, routing guards, or UI element masking.
- **Adopt Indirect Reference Maps:** Use cryptographically secure GUIDs/UUIDs or session-bound mapping dictionaries instead of sequential database primary keys in public interfaces.
- **Contextual Ownership Verification:** Always verify that the currently authenticated subject (user/tenant) owns the requested object.

### Secure Python Example
```python
# Unsafe IDOR pattern:
# record = db.query(Invoice).filter_by(id=request.json['invoice_id']).first()

# Safe ownership-checked authorization:
@app.route("/api/invoices/<uuid:invoice_id>", methods=["GET"])
@login_required
def get_invoice(invoice_id):
    invoice = db.query(Invoice).filter_by(
        id=invoice_id, 
        organization_id=current_user.organization_id
    ).first_or_404()
    return jsonify(invoice.to_dict())
```

### Secure Java Example
```java
// Spring Security Method-Level Authorization
@PreAuthorize("hasRole('ADMIN') or #order.customer.id == authentication.principal.id")
public Order getOrderDetails(Long orderId) {
    return orderRepository.findByIdAndTenantId(orderId, SecurityContext.getTenantId())
        .orElseThrow(() -> new AccessDeniedException("Access denied to requested resource"));
}
```

## Practical Inspection & Remediation Checklist
- Search for request parameters directly feeding database lookup queries without tenancy or user ID filters.
- Ensure all mutation operations (PUT, POST, DELETE) validate that the caller holds the appropriate capability/role.
