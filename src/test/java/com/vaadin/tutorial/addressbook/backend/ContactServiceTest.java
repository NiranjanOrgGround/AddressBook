package com.vaadin.tutorial.addressbook.backend;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Test class for ContactService - generates code coverage data
 */
public class ContactServiceTest {

    @Test
    public void testCreateDemoService() {
        ContactService service = ContactService.createDemoService();
        assertNotNull("Service should not be null", service);
        assertTrue("Should have contacts", service.count() > 0);
    }

    @Test
    public void testFindAll() {
        ContactService service = ContactService.createDemoService();
        assertEquals("Should find all contacts", 100, service.findAll("").size());
    }

    @Test
    public void testFindAllWithFilter() {
        ContactService service = ContactService.createDemoService();
        int allContacts = service.findAll("").size();
        int filteredContacts = service.findAll("Smith").size();
        assertTrue("Filtered contacts should be less than all", filteredContacts <= allContacts);
    }

    @Test
    public void testSaveNewContact() {
        ContactService service = ContactService.createDemoService();
        Contact contact = new Contact();
        contact.setFirstName("Test");
        contact.setLastName("User");
        contact.setEmail("test@example.com");
        
        long initialCount = service.count();
        service.save(contact);
        
        assertEquals("Count should increase", initialCount + 1, service.count());
    }

    @Test
    public void testDeleteContact() {
        ContactService service = ContactService.createDemoService();
        Contact contact = new Contact();
        contact.setFirstName("Delete");
        contact.setLastName("Me");
        service.save(contact);
        
        long countBeforeDelete = service.count();
        service.delete(contact);
        
        assertEquals("Count should decrease", countBeforeDelete - 1, service.count());
    }

    // Tests for vulnerable methods (to show they exist)
    @Test
    public void testInsecureToken() {
        ContactService service = new ContactService();
        String token = service.insecureToken();
        assertNotNull("Token should not be null", token);
        assertTrue("Token should have length", token.length() > 0);
    }

    @Test
    public void testWeakHash() throws Exception {
        ContactService service = new ContactService();
        String hash = service.weakHash("test");
        assertNotNull("Hash should not be null", hash);
        assertEquals("MD5 hash of 'test'", "098f6bcd4621d373cade4e832627b4f6", hash);
    }

    @Test
    public void testWeakHashDifferentInputs() throws Exception {
        ContactService service = new ContactService();
        String hash1 = service.weakHash("password1");
        String hash2 = service.weakHash("password2");
        assertNotEquals("Different inputs should produce different hashes", hash1, hash2);
    }
}
