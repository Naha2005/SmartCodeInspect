# OWASP Deserialization Cheat Sheet

Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
Retrieved: 2026-10-11
Author: OWASP Cheat Sheet Series Team

## Introduction
Serialization is the process of translating data structures or object state into a format that can be stored or transmitted across a network and reconstructed later. Deserialization is the reverse process: extracting a data structure from a series of bytes. Insecure deserialization is a vulnerability where untrusted data is used to inflict a denial of service, execute arbitrary code, or bypass authentication.

## Python Deserialization Guidance
Python's standard `pickle` module is explicitly not secure against erroneous or maliciously constructed data. The `pickle` protocol allows arbitrary Python objects to define `__reduce__` or `__reduce_ex__` methods, which direct the unpickler to invoke any callable with arbitrary arguments during deserialization.
```python
# VULNERABLE:
data = pickle.loads(untrusted_stream) # Remote Code Execution vulnerability!
```
Remediation:
1. Never unpickle untrusted data.
2. Use safe data exchange formats such as JSON, Protocol Buffers, or CBOR.
3. If YAML is used, always use `yaml.safe_load(data)` or `yaml.load(data, Loader=yaml.SafeLoader)`.

## Java Deserialization Guidance
Java native serialization using `ObjectInputStream.readObject()` permits the deserialization of complex object graphs. Attackers construct "gadget chains"—sequences of classes already present on the application classpath (e.g., Apache Commons Collections, Spring Framework, Groovy)—that trigger arbitrary method execution during object reconstruction.
```java
// VULNERABLE:
ObjectInputStream ois = new ObjectInputStream(untrustedInputStream);
Object obj = ois.readObject(); // RCE via gadget chains!
```
Remediation:
1. Do not accept Java serialized objects from untrusted sources.
2. If serialized objects must be received, implement `ValidatingObjectInputStream` or use the Java 9+ serialization filtering API (`java.io.ObjectInputFilter`).
3. Migrate to JSON (Jackson, Gson) or Protocol Buffers.
