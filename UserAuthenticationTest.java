import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;

/**
 * Comprehensive test suite for UserAuthentication class.
 * Tests verify current behavior including edge cases and boundary conditions.
 */
public class UserAuthenticationTest {

    private UserAuthentication auth;

    @Before
    public void setUp() {
        auth = new UserAuthentication();
    }

    // Tests for authenticateUser method

    @Test
    public void testAuthenticateUser_WithSQLInjectionAttempt() {
        // Test current behavior with SQL injection attempt
        // This test documents the vulnerability without fixing it
        boolean result = auth.authenticateUser("admin' OR '1'='1'; --", "anyPassword");
        // The method will return false due to SQLException (connection failure)
        assertFalse("SQL injection attempt should fail due to connection error", result);
    }

    @Test
    public void testAuthenticateUser_WithNormalCredentials() {
        // Test with normal username and password
        boolean result = auth.authenticateUser("normalUser", "password123");
        // Will return false due to database connection failure
        assertFalse("Authentication should fail due to no database connection", result);
    }

    @Test
    public void testAuthenticateUser_WithEmptyUsername() {
        // Edge case: empty username
        boolean result = auth.authenticateUser("", "password");
        assertFalse("Empty username should fail authentication", result);
    }

    @Test
    public void testAuthenticateUser_WithEmptyPassword() {
        // Edge case: empty password
        boolean result = auth.authenticateUser("user", "");
        assertFalse("Empty password should fail authentication", result);
    }

    @Test
    public void testAuthenticateUser_WithNullUsername() {
        // Edge case: null username
        boolean result = auth.authenticateUser(null, "password");
        assertFalse("Null username should fail authentication", result);
    }

    @Test
    public void testAuthenticateUser_WithNullPassword() {
        // Edge case: null password
        boolean result = auth.authenticateUser("user", null);
        assertFalse("Null password should fail authentication", result);
    }

    @Test
    public void testAuthenticateUser_WithSpecialCharacters() {
        // Test with special characters in credentials
        boolean result = auth.authenticateUser("user@example.com", "P@ssw0rd!");
        assertFalse("Special characters should be handled", result);
    }

    // Tests for processUserData method

    @Test
    public void testProcessUserData_WithNormalData() {
        // Test that method executes without throwing exception
        try {
            auth.processUserData("Normal user data");
            // If we reach here, no exception was thrown
            assertTrue("Method should execute successfully", true);
        } catch (Exception e) {
            fail("Should not throw exception: " + e.getMessage());
        }
    }

    @Test
    public void testProcessUserData_WithEmptyString() {
        // Edge case: empty string
        try {
            auth.processUserData("");
            assertTrue("Should handle empty string", true);
        } catch (Exception e) {
            fail("Should not throw exception with empty string: " + e.getMessage());
        }
    }

    @Test
    public void testProcessUserData_WithLargeData() {
        // Test with large data string
        StringBuilder largeData = new StringBuilder();
        for (int i = 0; i < 10000; i++) {
            largeData.append("data");
        }
        try {
            auth.processUserData(largeData.toString());
            assertTrue("Should handle large data", true);
        } catch (Exception e) {
            fail("Should not throw exception with large data: " + e.getMessage());
        }
    }

    @Test
    public void testProcessUserData_WithSpecialCharacters() {
        // Test with special characters
        try {
            auth.processUserData("Data with special chars: <>&\"'");
            assertTrue("Should handle special characters", true);
        } catch (Exception e) {
            fail("Should not throw exception with special chars: " + e.getMessage());
        }
    }

    @Test(expected = NullPointerException.class)
    public void testProcessUserData_WithNull() {
        // Edge case: null input should throw NullPointerException
        auth.processUserData(null);
    }

    // Tests for getUsername method

    @Test(expected = NullPointerException.class)
    public void testGetUsername_ThrowsNullPointerException() {
        // This test documents the bug where username is always null
        // Line 38: username.length() will throw NPE since username is null
        auth.getUsername(1);
    }

    @Test(expected = NullPointerException.class)
    public void testGetUsername_WithZeroUserId() {
        // Edge case: userId = 0
        auth.getUsername(0);
    }

    @Test(expected = NullPointerException.class)
    public void testGetUsername_WithNegativeUserId() {
        // Edge case: negative userId
        auth.getUsername(-1);
    }

    @Test(expected = NullPointerException.class)
    public void testGetUsername_WithLargeUserId() {
        // Boundary case: large userId
        auth.getUsername(Integer.MAX_VALUE);
    }

    // Tests for addNumbers method

    @Test
    public void testAddNumbers_PositiveNumbers() {
        // Test basic addition with positive numbers
        int result = auth.addNumbers(5, 7);
        assertEquals("5 + 7 should equal 12", 12, result);
    }

    @Test
    public void testAddNumbers_NegativeNumbers() {
        // Test with negative numbers
        int result = auth.addNumbers(-5, -7);
        assertEquals("-5 + -7 should equal -12", -12, result);
    }

    @Test
    public void testAddNumbers_MixedSignNumbers() {
        // Test with mixed positive and negative
        int result = auth.addNumbers(10, -3);
        assertEquals("10 + -3 should equal 7", 7, result);
    }

    @Test
    public void testAddNumbers_WithZero() {
        // Edge case: adding zero
        int result = auth.addNumbers(5, 0);
        assertEquals("5 + 0 should equal 5", 5, result);
    }

    @Test
    public void testAddNumbers_BothZero() {
        // Edge case: both numbers are zero
        int result = auth.addNumbers(0, 0);
        assertEquals("0 + 0 should equal 0", 0, result);
    }

    @Test
    public void testAddNumbers_MaxIntValues() {
        // Boundary case: large numbers (overflow scenario)
        int result = auth.addNumbers(Integer.MAX_VALUE, 1);
        // This will overflow to negative (documents integer overflow behavior)
        assertEquals("Overflow behavior", Integer.MIN_VALUE, result);
    }

    @Test
    public void testAddNumbers_LargePositiveNumbers() {
        // Test with large but non-overflowing numbers
        int result = auth.addNumbers(1000000, 2000000);
        assertEquals("Large number addition", 3000000, result);
    }

    // Tests for retrieveSensitiveInfo method

    @Test
    public void testRetrieveSensitiveInfo_WithPositiveUserId() {
        // Test retrieval with positive user ID
        String result = auth.retrieveSensitiveInfo(1);
        assertNotNull("Result should not be null", result);
        assertEquals("Should return formatted string", "Sensitive information for user 1", result);
    }

    @Test
    public void testRetrieveSensitiveInfo_WithZeroUserId() {
        // Edge case: userId = 0
        String result = auth.retrieveSensitiveInfo(0);
        assertNotNull("Result should not be null", result);
        assertEquals("Should handle zero userId", "Sensitive information for user 0", result);
    }

    @Test
    public void testRetrieveSensitiveInfo_WithNegativeUserId() {
        // Edge case: negative userId
        String result = auth.retrieveSensitiveInfo(-1);
        assertNotNull("Result should not be null", result);
        assertEquals("Should handle negative userId", "Sensitive information for user -1", result);
    }

    @Test
    public void testRetrieveSensitiveInfo_WithLargeUserId() {
        // Boundary case: large userId
        String result = auth.retrieveSensitiveInfo(999999);
        assertNotNull("Result should not be null", result);
        assertTrue("Should contain userId", result.contains("999999"));
    }

    // Tests for sendDataOverInsecureChannel method

    @Test
    public void testSendDataOverInsecureChannel_WithNormalData() {
        // Test that method executes without exception
        try {
            auth.sendDataOverInsecureChannel("Normal data");
            assertTrue("Should execute successfully", true);
        } catch (Exception e) {
            fail("Should not throw exception: " + e.getMessage());
        }
    }

    @Test
    public void testSendDataOverInsecureChannel_WithEmptyString() {
        // Edge case: empty string
        try {
            auth.sendDataOverInsecureChannel("");
            assertTrue("Should handle empty string", true);
        } catch (Exception e) {
            fail("Should not throw exception: " + e.getMessage());
        }
    }

    @Test
    public void testSendDataOverInsecureChannel_WithNull() {
        // Edge case: null input
        try {
            auth.sendDataOverInsecureChannel(null);
            assertTrue("Should handle null", true);
        } catch (Exception e) {
            fail("Should not throw exception with null: " + e.getMessage());
        }
    }

    @Test
    public void testSendDataOverInsecureChannel_WithSensitiveData() {
        // Test with sensitive-looking data
        try {
            auth.sendDataOverInsecureChannel("Password: secret123");
            assertTrue("Should handle sensitive data", true);
        } catch (Exception e) {
            fail("Should not throw exception: " + e.getMessage());
        }
    }

    // Tests for inadequatePasswordHashing method

    @Test
    public void testInadequatePasswordHashing_WithNormalPassword() {
        // Test MD5 hashing with normal password
        String result = auth.inadequatePasswordHashing("password123");
        assertNotNull("Hash should not be null", result);
        assertEquals("MD5 hash should be 32 characters", 32, result.length());
        // MD5 of "password123" is known
        assertEquals("Should produce correct MD5 hash", "482C811DA5D5B4BC6D497FFA98491E38", result);
    }

    @Test
    public void testInadequatePasswordHashing_WithEmptyPassword() {
        // Edge case: empty password
        String result = auth.inadequatePasswordHashing("");
        assertNotNull("Hash should not be null", result);
        assertEquals("Should hash empty string", 32, result.length());
        // MD5 of empty string
        assertEquals("MD5 of empty string", "D41D8CD98F00B204E9800998ECF8427E", result);
    }

    @Test
    public void testInadequatePasswordHashing_WithSpecialCharacters() {
        // Test with special characters
        String result = auth.inadequatePasswordHashing("P@ssw0rd!");
        assertNotNull("Hash should not be null", result);
        assertEquals("Should handle special characters", 32, result.length());
    }

    @Test
    public void testInadequatePasswordHashing_WithLongPassword() {
        // Test with long password
        StringBuilder longPassword = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            longPassword.append("a");
        }
        String result = auth.inadequatePasswordHashing(longPassword.toString());
        assertNotNull("Hash should not be null", result);
        assertEquals("Should handle long password", 32, result.length());
    }

    @Test
    public void testInadequatePasswordHashing_ConsistentOutput() {
        // Test that same input produces same hash
        String hash1 = auth.inadequatePasswordHashing("test");
        String hash2 = auth.inadequatePasswordHashing("test");
        assertEquals("Same input should produce same hash", hash1, hash2);
    }

    @Test
    public void testInadequatePasswordHashing_DifferentInputsDifferentHashes() {
        // Test that different inputs produce different hashes
        String hash1 = auth.inadequatePasswordHashing("password1");
        String hash2 = auth.inadequatePasswordHashing("password2");
        assertNotEquals("Different inputs should produce different hashes", hash1, hash2);
    }

    @Test
    public void testInadequatePasswordHashing_WithUnicodeCharacters() {
        // Test with Unicode characters
        String result = auth.inadequatePasswordHashing("パスワード");
        assertNotNull("Should handle Unicode", result);
        assertEquals("Should produce valid hash", 32, result.length());
    }
}