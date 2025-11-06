package com.vaadin.tutorial.addressbook.backend;

import java.io.IOException;

/**
 * SECURITY TEST CLASS - INTENTIONALLY VULNERABLE
 * This class demonstrates usage of vulnerable code patterns
 * to test GHAS CodeQL and SonarQube detection capabilities
 */
public class SecurityTestDriver {

    public static void main(String[] args) {
        testVulnerabilities();
    }

    public static void testVulnerabilities() {
        try {
            // Test hardcoded credentials exposure
            String apiKey = "sk-1234567890abcdef"; // Hardcoded API key
            String password = "SuperSecret123!"; // Hardcoded password
            
            // Test weak random number generation
            String token = VulnerableUtils.generateSessionToken();
            System.out.println("Generated token: " + token);
            
            // Test SQL injection vulnerability
            String maliciousInput = "admin' OR '1'='1";
            VulnerableUtils.unsafeLogin(maliciousInput, "anything");
            
            // Test command injection
            String command = "ls -la; cat /etc/passwd";
            VulnerableUtils.executeCommand(command);
            
            // Test path traversal
            String fileName = "../../../etc/passwd";
            VulnerableUtils.readFile(fileName);
            
            // Test weak encryption
            VulnerableUtils.encryptWithDES("sensitive data", "weakkey");
            
            // Test XSS vulnerability
            String userInput = "<script>alert('XSS')</script>";
            VulnerableUtils.generateHTML(userInput);
            
            // Test SSRF vulnerability
            VulnerableUtils.fetchURL("http://internal-server/admin");
            
            // Test null pointer dereference
            String nullString = null;
            VulnerableUtils.getStringLength(nullString); // Will throw NPE
            
            // Test logging sensitive data
            VulnerableUtils.logUserCredentials("admin", "password123");
            
            // Test weak hashing
            VulnerableUtils.hashPassword("mypassword");
            
            // Test certificate validation bypass
            VulnerableUtils.disableSSLValidation();
            
        } catch (Exception e) {
            e.printStackTrace();
            // Poor exception handling - exposing stack trace
        }
    }
    
    // Additional vulnerable pattern: Empty catch block (CWE-391)
    public static void ignoreExceptions() {
        try {
            riskyOperation();
        } catch (Exception e) {
            // Empty catch block - vulnerability
        }
    }
    
    private static void riskyOperation() throws IOException {
        throw new IOException("Something went wrong");
    }
    
    // Hard-coded password in method (CWE-259)
    public static boolean checkPassword(String input) {
        String hardcodedPassword = "admin123";
        return input.equals(hardcodedPassword);
    }
    
    // Resource leak (CWE-404)
    public static void leakResource(String filename) throws Exception {
        java.io.FileInputStream fis = new java.io.FileInputStream(filename);
        // File stream not closed - resource leak
        fis.read();
    }
}
