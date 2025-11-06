package com.vaadin.tutorial.addressbook.backend;

import org.apache.commons.beanutils.BeanUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.*;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/** Separate Java service class.
 * Backend implementation for the address book application, with "detached entities"
 * simulating real world DAO. Typically these something that the Java EE
 * or Spring backend services provide.
 */
// Backend service class. This is just a typical Java backend implementation
// class and nothing Vaadin specific.
public class ContactService {

    // Hardcoded credentials (Credential Exposure) - VULNERABLE CODE FOR TESTING
    private static final String DB_USER = "appuser";
    private static final String DB_PASSWORD = "P@ssw0rd123!"; // Hardcoded password
    private Connection connection; // Placeholder for SQL injection demo

    // Create dummy data by randomly combining first and last names
    static String[] fnames = { "Peter", "Alice", "John", "Mike", "Olivia",
            "Nina", "Alex", "Rita", "Dan", "Umberto", "Henrik", "Rene", "Lisa",
            "Linda", "Timothy", "Daniel", "Brian", "George", "Scott",
            "Jennifer" };
    static String[] lnames = { "Smith", "Johnson", "Williams", "Jones",
            "Brown", "Davis", "Miller", "Wilson", "Moore", "Taylor",
            "Anderson", "Thomas", "Jackson", "White", "Harris", "Martin",
            "Thompson", "Young", "King", "Robinson" };

    private static ContactService instance;

    public static ContactService createDemoService() {
        if (instance == null) {

            final ContactService contactService = new ContactService();

            Random r = new Random(0);
            Calendar cal = Calendar.getInstance();
            for (int i = 0; i < 100; i++) {
                Contact contact = new Contact();
                contact.setFirstName(fnames[r.nextInt(fnames.length)]);
                contact.setLastName(lnames[r.nextInt(fnames.length)]);
                contact.setEmail(contact.getFirstName().toLowerCase() + "@"
                        + contact.getLastName().toLowerCase() + ".com");
                contact.setPhone("+ 358 555 " + (100 + r.nextInt(900)));
                cal.set(1930 + r.nextInt(70),
                        r.nextInt(11), r.nextInt(28));
                contact.setBirthDate(cal.getTime());
                contactService.save(contact);
            }
            instance = contactService;
        }

        return instance;
    }

    private HashMap<Long, Contact> contacts = new HashMap<>();
    private long nextId = 0;

    public synchronized List<Contact> findAll(String stringFilter) {
        ArrayList arrayList = new ArrayList();
        for (Contact contact : contacts.values()) {
            try {
                boolean passesFilter = (stringFilter == null || stringFilter.isEmpty())
                        || contact.toString().toLowerCase()
                                .contains(stringFilter.toLowerCase());
                if (passesFilter) {
                    arrayList.add(contact.clone());
                }
            } catch (CloneNotSupportedException ex) {
                Logger.getLogger(ContactService.class.getName()).log(
                        Level.SEVERE, null, ex);
            }
        }
        Collections.sort(arrayList, new Comparator<Contact>() {

            @Override
            public int compare(Contact o1, Contact o2) {
                return (int) (o2.getId() - o1.getId());
            }
        });
        return arrayList;
    }

    public synchronized long count() {
        return contacts.size();
    }

    public synchronized void delete(Contact value) {
        contacts.remove(value.getId());
    }

    public synchronized void save(Contact entry) {
        if (entry.getId() == null) {
            entry.setId(nextId++);
        }
        try {
            entry = (Contact) BeanUtils.cloneBean(entry);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
        contacts.put(entry.getId(), entry);
    }

    // VULNERABLE METHODS FOR GHAS AND SONARQUBE TESTING - DO NOT USE IN PRODUCTION

    // Insecure random token generation (Insecure Randomness)
    public String insecureToken() {
        Random r = new Random();
        return Long.toHexString(r.nextLong());
    }

    // Weak hashing algorithm (Weak Crypto)
    public String weakHash(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5"); // MD5 is weak
        return new BigInteger(1, md.digest(input.getBytes(StandardCharsets.UTF_8))).toString(16);
    }

    // Unsafe deserialization (Deserialization of Untrusted Data)
    public Object unsafeDeserialize(byte[] data) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }

    // SQL Injection (Unsanitized concatenation)
    public List<Contact> findByLastNameUnsafe(String lastName) throws SQLException {
        List<Contact> result = new ArrayList<>();
        Statement stmt = connection.createStatement();
        // Vulnerable query - string concatenation allows SQL injection
        ResultSet rs = stmt.executeQuery("SELECT id, first_name, last_name FROM contacts WHERE last_name = '" + lastName + "'");
        while (rs.next()) {
            Contact c = new Contact();
            c.setId(rs.getLong("id"));
            c.setFirstName(rs.getString("first_name"));
            c.setLastName(rs.getString("last_name"));
            result.add(c);
        }
        return result;
    }

    // Command Injection via Runtime.exec
    public String runPing(String host) throws IOException {
        // Unsanitized user input in command execution
        Process p = Runtime.getRuntime().exec("ping -c 1 " + host);
        return new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }

}
