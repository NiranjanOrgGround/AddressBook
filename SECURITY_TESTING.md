# Security Testing - Intentional Vulnerabilities

⚠️ **WARNING: This code contains intentional security vulnerabilities for testing purposes only!**

## Purpose
This repository has been modified to include intentionally vulnerable code to test:
- GitHub Advanced Security (GHAS) CodeQL analysis
- SonarQube security scanning

## Vulnerable Files Added/Modified

### 1. `ContactService.java`
- **Hardcoded Credentials** (CWE-798): Database username and password
- **SQL Injection** (CWE-89): `findByLastNameUnsafe()` method
- **Command Injection** (CWE-78): `runPing()` method
- **Weak Cryptography** (CWE-327): `weakHash()` using MD5
- **Insecure Randomness** (CWE-330): `insecureToken()` using Random instead of SecureRandom
- **Unsafe Deserialization** (CWE-502): `unsafeDeserialize()` method

### 2. `VulnerableUtils.java` (NEW)
Contains 20+ security vulnerabilities:
- CWE-798: Hardcoded Credentials (database, API keys, tokens)
- CWE-327: Weak Encryption (DES algorithm)
- CWE-330: Insecure Random Number Generation
- CWE-89: SQL Injection
- CWE-78: OS Command Injection
- CWE-22: Path Traversal
- CWE-502: Unsafe Deserialization
- CWE-611: XML External Entity (XXE)
- CWE-601: Open Redirect
- CWE-79: Cross-Site Scripting (XSS)
- CWE-190: Integer Overflow
- CWE-476: NULL Pointer Dereference
- CWE-400: Resource Exhaustion
- CWE-532: Information Exposure in Logs
- CWE-295: Improper Certificate Validation
- CWE-918: Server-Side Request Forgery (SSRF)
- CWE-326: Weak Encryption Strength
- CWE-759: Password Hashing without Salt
- CWE-307: No Authentication Rate Limiting
- CWE-352: Missing CSRF Protection

### 3. `SecurityTestDriver.java` (NEW)
Demonstrates usage of vulnerable methods:
- Empty catch blocks
- Hardcoded passwords
- Resource leaks
- Null pointer dereferences
- Sensitive data logging

### 4. `AddressbookUI.java`
- Vulnerable test panel reading unsanitized query parameters
- Calls to vulnerable methods

### 5. `.github/workflows/codeql.yml`
- Enabled `security-extended` and `security-and-quality` query packs

## How to Trigger Code Scanning

### Option 1: Push to GitHub
```bash
git add .
git commit -m "Add vulnerable code for security testing"
git push origin main
```

### Option 2: Manual Trigger
1. Go to GitHub repository → Actions tab
2. Select "CodeQL Advanced" workflow
3. Click "Run workflow"

### Option 3: Wait for Scheduled Scan
The workflow runs on schedule: Every Friday at 22:28 UTC

## Expected Security Alerts

After CodeQL analysis completes, you should see alerts for:

### Critical Severity:
- SQL Injection
- Command Injection
- Hardcoded credentials
- Unsafe deserialization
- XXE vulnerabilities

### High Severity:
- Weak cryptographic algorithms (MD5, DES)
- Path traversal
- SSRF vulnerabilities
- Open redirects
- XSS vulnerabilities

### Medium Severity:
- Insecure random number generation
- Information exposure in logs
- Missing input validation
- Resource leaks

### Low Severity:
- Empty catch blocks
- Null pointer risks
- Integer overflow risks

## Viewing Results

### GitHub Advanced Security (GHAS):
1. Navigate to repository → Security tab
2. Click "Code scanning alerts"
3. Filter by severity, rule type, or tool

### SonarQube:
1. Configure SonarQube to scan this repository
2. Run analysis: `mvn sonar:sonar`
3. View results in SonarQube dashboard

## Cleanup

**BEFORE PRODUCTION:** Remove or comment out all vulnerable code:
```bash
# Remove vulnerable files
rm src/main/java/com/vaadin/tutorial/addressbook/backend/VulnerableUtils.java
rm src/main/java/com/vaadin/tutorial/addressbook/backend/SecurityTestDriver.java

# Restore original ContactService.java and AddressbookUI.java
git checkout HEAD~1 -- src/main/java/com/vaadin/tutorial/addressbook/backend/ContactService.java
git checkout HEAD~1 -- src/main/java/com/vaadin/tutorial/addressbook/AddressbookUI.java
```

## Notes
- These vulnerabilities are INTENTIONAL for testing security scanning tools
- DO NOT deploy this code to production
- DO NOT use these patterns in real applications
- The vulnerable code demonstrates what NOT to do in secure development

## References
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning)
- [CodeQL documentation](https://codeql.github.com/docs/)
