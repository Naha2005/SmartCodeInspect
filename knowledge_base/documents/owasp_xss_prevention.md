# OWASP Cross-Site Scripting (XSS) Prevention Cheat Sheet

Source: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
Retrieved: 2026-10-11
Author: OWASP Cheat Sheet Series Team

## Introduction
Cross-Site Scripting (XSS) is a type of injection attack in which malicious scripts are injected into otherwise benign and trusted websites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user.

## Types of XSS
- **Stored XSS:** The malicious input is permanently stored on the target servers (e.g. database, comment field, forum post) and delivered to victims when requesting the stored information.
- **Reflected XSS:** The malicious payload is reflected off a web application into the user's browser via error messages, search results, or URL parameters.
- **DOM-based XSS:** The vulnerability exists in client-side code rather than server-side code, where client JavaScript reads data from an untrusted source (like `location.search` or `document.URL`) and writes it to an execution sink (like `innerHTML` or `document.write`).

## Framework Security and Context-Aware Encoding
Modern web frameworks (e.g. React, Angular, Vue) automatically encode variables in templates by default, neutralizing most classic reflected and stored XSS vectors. For example, JSX in React automatically escapes strings before rendering them to the DOM:
```jsx
// SAFE in React: automatically escaped
<div>{untrustedUserInput}</div>
```
However, using unsafe sinks bypasses framework protections:
```jsx
// VULNERABLE in React:
<div dangerouslySetInnerHTML={{ __html: untrustedUserInput }} />
```

## Content Security Policy (CSP)
Implement a robust Content Security Policy (CSP) HTTP response header. CSP provides defense-in-depth by restricting where scripts can be loaded from and disabling the execution of inline scripts (`unsafe-inline`) and `eval()`.
