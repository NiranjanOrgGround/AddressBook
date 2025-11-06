package com.vaadin.tutorial.addressbook.backend;

import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;

/**
 * Test class for ContactService - generates code coverage data
 */
public class ContactServiceTest {

    private ContactService service;

    @Before
    public void setUp() {
        // Create a fresh service instance for each test
        service = ContactService.createDemoService();
    }

    @Test
    public void testCreateDemoService() {
        assertNotNull("Service should not be null", service);
        assertTrue("Should have contacts", service.count() > 0);
    }

    @Test
    public void testFindAll() {
        // The demo service creates 100 contacts initially
        assertTrue("Should have at least 100 contacts", service.findAll("").size() >= 100);
    }

    @Test
    public void testFindAllWithFilter() {
        int allContacts = service.findAll("").size();
        int filteredContacts = service.findAll("Smith").size();
        assertTrue("Filtered contacts should be less than or equal to all", filteredContacts <= allContacts);
    }

    @Test
    public void testSaveNewContact() {
        long initialCount = service.count();
        
        Contact contact = new Contact();
        contact.setFirstName("Test");
        contact.setLastName("User");
        contact.setEmail("test@example.com");
        
        service.save(contact);
        
        assertEquals("Count should increase by 1", initialCount + 1, service.count());
    }

    @Test
    public void testDeleteContact() {
        Contact contact = new Contact();
        contact.setFirstName("Delete");
        contact.setLastName("Me");
        service.save(contact);
        
        long countBeforeDelete = service.count();
        service.delete(contact);
        
        assertEquals("Count should decrease by 1", countBeforeDelete - 1, service.count());
    }

    // Tests for vulnerable methods (to show they exist)
    @Test
    public void testInsecureToken() {
        ContactService testService = new ContactService();
        String token = testService.insecureToken();
        assertNotNull("Token should not be null", token);
        assertTrue("Token should have length", token.length() > 0);
    }

    @Test
    public void testWeakHash() throws Exception {
        ContactService testService = new ContactService();
        String hash = testService.weakHash("test");
        assertNotNull("Hash should not be null", hash);
        // MD5 hash of 'test' should be 32 characters
        assertEquals("Hash should be 32 characters", 32, hash.length());
        assertEquals("MD5 hash of 'test'", "098f6bcd4621d373cade4e832627b4f6", hash);
    }

    @Test
    public void testWeakHashDifferentInputs() throws Exception {
        ContactService testService = new ContactService();
        String hash1 = testService.weakHash("password1");
        String hash2 = testService.weakHash("password2");
        assertNotEquals("Different inputs should produce different hashes", hash1, hash2);
    }
}
