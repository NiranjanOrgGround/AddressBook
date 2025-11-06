package com.vaadin.tutorial.addressbook.backend;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.URL;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Random;

/**
 * INTENTIONALLY VULNERABLE CODE FOR SECURITY TESTING
 * DO NOT USE IN PRODUCTION
 * This class contains multiple security vulnerabilities for testing GHAS CodeQL and SonarQube
 */
public class VulnerableUtils {

    // CWE-798: Hardcoded Credentials
    private static final String DATABASE_URL = "jdbc:mysql://localhost:3306/addressbook";
    private static final String DATABASE_USER = "root";
    private static final String DATABASE_PASSWORD = "admin123"; // Hardcoded password
    private static final String API_KEY = "sk-1234567890abcdef"; // Hardcoded API key
    private static final String SECRET_TOKEN = "my-secret-token-12345"; // Hardcoded secret

    // CWE-327: Use of a Broken or Risky Cryptographic Algorithm
    public static String encryptWithDES(String data, String key) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES"); // Weak encryption
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return new String(encrypted);
    }

    // CWE-330: Use of Insufficiently Random Values
    public static String generateSessionToken() {
        Random random = new Random(); // Should use SecureRandom
        return "SESSION-" + random.nextInt(999999);
    }

    // CWE-330: Predictable seed
    public static int generateRandomNumber() {
        Random random = new Random(System.currentTimeMillis()); // Predictable seed
        return random.nextInt();
    }

    // CWE-89: SQL Injection
    public static void unsafeLogin(String username, String password) throws Exception {
        Connection conn = DriverManager.getConnection(DATABASE_URL, DATABASE_USER, DATABASE_PASSWORD);
        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        // Direct string concatenation - SQL injection vulnerability
        PreparedStatement stmt = conn.prepareStatement(query);
        ResultSet rs = stmt.executeQuery();
        // Process results...
    }

    // CWE-78: OS Command Injection
    public static String executeCommand(String userInput) throws IOException {
        // Directly passing user input to system command
        Process process = Runtime.getRuntime().exec("cmd.exe /c " + userInput);
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }

    // CWE-22: Path Traversal
    public static String readFile(String fileName) throws IOException {
        // No validation - allows path traversal attacks like "../../../etc/passwd"
        File file = new File("/var/app/uploads/" + fileName);
        BufferedReader reader = new BufferedReader(new FileReader(file));
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line).append("\n");
        }
        reader.close();
        return content.toString();
    }

    // CWE-502: Deserialization of Untrusted Data
    public static Object deserializeObject(byte[] data) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis);
        return ois.readObject(); // Unsafe deserialization
    }

    // CWE-611: XML External Entity (XXE) Injection
    public static void parseXML(String xmlContent) throws Exception {
        javax.xml.parsers.DocumentBuilderFactory factory = 
            javax.xml.parsers.DocumentBuilderFactory.newInstance();
        // XXE vulnerability - external entities not disabled
        javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
        java.io.ByteArrayInputStream input = new java.io.ByteArrayInputStream(xmlContent.getBytes());
        builder.parse(input);
    }

    // CWE-601: URL Redirection to Untrusted Site
    public static void redirect(String url) throws IOException {
        // No validation - open redirect vulnerability
        java.awt.Desktop.getDesktop().browse(java.net.URI.create(url));
    }

    // CWE-079: Cross-Site Scripting (XSS)
    public static String generateHTML(String userInput) {
        // No HTML encoding - XSS vulnerability
        return "<html><body><h1>Welcome " + userInput + "</h1></body></html>";
    }

    // CWE-190: Integer Overflow
    public static int calculateTotal(int a, int b) {
        return a + b; // No overflow check
    }

    // CWE-476: NULL Pointer Dereference
    public static int getStringLength(String str) {
        return str.length(); // No null check
    }

    // CWE-400: Uncontrolled Resource Consumption
    public static void processUserData(int count) {
        // No limit on resource allocation
        byte[][] arrays = new byte[count][1024 * 1024]; // Could cause OutOfMemoryError
    }

    // CWE-532: Information Exposure Through Log Files
    public static void logUserCredentials(String username, String password) {
        System.out.println("User login: " + username + " with password: " + password);
        // Logging sensitive information
    }

    // CWE-295: Improper Certificate Validation
    public static void disableSSLValidation() throws Exception {
        javax.net.ssl.TrustManager[] trustAllCerts = new javax.net.ssl.TrustManager[]{
            new javax.net.ssl.X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) { }
                public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) { }
            }
        };
        javax.net.ssl.SSLContext sc = javax.net.ssl.SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    }

    // CWE-918: Server-Side Request Forgery (SSRF)
    public static String fetchURL(String userProvidedURL) throws IOException {
        URL url = new URL(userProvidedURL); // No URL validation
        BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line);
        }
        reader.close();
        return content.toString();
    }

    // CWE-326: Inadequate Encryption Strength
    public static String weakEncryption(String data) throws Exception {
        SecretKeySpec key = new SecretKeySpec("12345678".getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding"); // Weak algorithm and mode
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return new String(cipher.doFinal(data.getBytes()));
    }

    // CWE-759: Use of a One-Way Hash without a Salt
    public static String hashPassword(String password) throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-1");
        byte[] hash = md.digest(password.getBytes()); // No salt
        return new String(hash);
    }

    // CWE-307: Improper Restriction of Excessive Authentication Attempts
    public static boolean authenticate(String username, String password) {
        // No rate limiting or account lockout
        return DATABASE_USER.equals(username) && DATABASE_PASSWORD.equals(password);
    }

    // CWE-352: Cross-Site Request Forgery (CSRF)
    public static void processFormSubmission(String action, String data) {
        // No CSRF token validation
        System.out.println("Processing: " + action + " with data: " + data);
    }
}
