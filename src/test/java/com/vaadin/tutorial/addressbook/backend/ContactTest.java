package com.vaadin.tutorial.addressbook.backend;

import org.junit.Test;
import java.util.Date;
import static org.junit.Assert.*;

/**
 * Test class for Contact entity
 */
public class ContactTest {

    @Test
    public void testContactCreation() {
        Contact contact = new Contact();
        assertNotNull("Contact should not be null", contact);
    }

    @Test
    public void testContactGettersSetters() {
        Contact contact = new Contact();
        
        contact.setId(1L);
        contact.setFirstName("John");
        contact.setLastName("Doe");
        contact.setEmail("john.doe@example.com");
        contact.setPhone("+1234567890");
        Date birthDate = new Date();
        contact.setBirthDate(birthDate);
        
        assertEquals("ID should match", Long.valueOf(1L), contact.getId());
        assertEquals("First name should match", "John", contact.getFirstName());
        assertEquals("Last name should match", "Doe", contact.getLastName());
        assertEquals("Email should match", "john.doe@example.com", contact.getEmail());
        assertEquals("Phone should match", "+1234567890", contact.getPhone());
        assertEquals("Birth date should match", birthDate, contact.getBirthDate());
    }

    @Test
    public void testContactToString() {
        Contact contact = new Contact();
        contact.setFirstName("Jane");
        contact.setLastName("Smith");
        
        String toString = contact.toString();
        assertNotNull("toString should not be null", toString);
        assertTrue("toString should contain first name", toString.contains("Jane"));
        assertTrue("toString should contain last name", toString.contains("Smith"));
    }

    @Test
    public void testContactClone() throws CloneNotSupportedException {
        Contact original = new Contact();
        original.setId(1L);
        original.setFirstName("Clone");
        original.setLastName("Test");
        original.setEmail("clone@test.com");
        
        Contact cloned = (Contact) original.clone();
        
        assertNotNull("Cloned contact should not be null", cloned);
        assertEquals("Cloned first name should match", original.getFirstName(), cloned.getFirstName());
        assertEquals("Cloned last name should match", original.getLastName(), cloned.getLastName());
        assertEquals("Cloned email should match", original.getEmail(), cloned.getEmail());
    }

    @Test
    public void testContactDefaultValues() {
        Contact contact = new Contact();
        
        assertEquals("Default first name should be empty", "", contact.getFirstName());
        assertEquals("Default last name should be empty", "", contact.getLastName());
        assertEquals("Default phone should be empty", "", contact.getPhone());
        assertEquals("Default email should be empty", "", contact.getEmail());
        assertNull("Default ID should be null", contact.getId());
        assertNull("Default birth date should be null", contact.getBirthDate());
    }
}
