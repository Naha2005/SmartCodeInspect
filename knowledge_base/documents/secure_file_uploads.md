# OWASP Secure File Upload Cheat Sheet

Source: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
Retrieved: 2026-10-12
Author: OWASP Cheat Sheet Series Team
Topic: Secure File Uploads

## Introduction
Allowing users to upload files is a powerful capability but introduces critical risks if files are executed on the host server, stored in publicly accessible paths, or permitted to exhaust server storage resources.

## Vulnerabilities and Threat Scenarios
1. **Remote Code Execution (RCE):** Uploading executable scripts (`.php`, `.jsp`, `.py`, `.exe`, `.cgi`) to web roots where web servers execute them on request.
2. **Denial of Service (DoS):** Uploading excessively large files or decompression bombs ("zip bombs") to exhaust server memory or disk storage.
3. **Stored Cross-Site Scripting (XSS):** Uploading HTML, SVG, or PDF files containing malicious JavaScript that executes when viewed in a browser context.
4. **MIME-Type Spoofing:** Supplying a forged `Content-Type: image/jpeg` header for an uploaded binary payload.

## Defense-in-Depth Prevention Controls

### 1. File Type and Extension Allow-listing
Never rely on blacklists (`.php`, `.exe`). Define an explicit allow-list of safe extensions (`.png`, `.jpg`, `.pdf`). Verify the file magic numbers / binary signature, not merely the filename extension or HTTP `Content-Type` header.

### 2. Randomize Stored Filenames
Never store files on disk using the original client-provided filename. Generate an independent random UUID or cryptographically strong identifier.

### 3. Store Files Outside the Web Root
Store uploaded assets in a dedicated non-executable directory or remote cloud object store (e.g. S3 bucket) with private permissions.

### Secure Python Upload Processing Example
```python
import uuid
from pathlib import Path
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".pdf"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
STORAGE_DIR = Path("/var/app/storage/uploads").resolve()

def process_secure_upload(file_storage) -> str:
    original_name = secure_filename(file_storage.filename)
    suffix = Path(original_name).suffix.lower()
    
    if suffix not in ALLOWED_EXTENSIONS:
        raise ValueError("Unsupported or forbidden file format")

    # Read and enforce size limit
    content = file_storage.read(MAX_FILE_SIZE + 1)
    if len(content) > MAX_FILE_SIZE:
        raise ValueError("File exceeds maximum allowed size (5MB)")

    # Save under random UUID
    unique_name = f"{uuid.uuid4().hex}{suffix}"
    dest_path = (STORAGE_DIR / unique_name).resolve()
    dest_path.write_bytes(content)
    
    return unique_name
```

## Remediation Checklist
- Serve user uploads with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff` to prevent browser script execution.
- Set strict filesystem permissions (`chmod 0640`) on uploaded files and mount the upload folder with the `noexec` flag.
