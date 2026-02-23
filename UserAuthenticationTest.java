import org.junit.Test;
import org.junit.Before;
import org.junit.After;
import static org.junit.Assert.*;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

/**
 * Comprehensive test suite for UserAuthentication class.
 * Tests cover normal functionality, edge cases, and known vulnerabilities.
 */
public class UserAuthenticationTest {

    private UserAuthentication auth;
    private final ByteArrayOutputStream outContent = new ByteArrayOutputStream();
    private final PrintStream originalOut = System.out;

    @Before
    public void setUp() {
        auth = new UserAuthentication();
        System.setOut(new PrintStream(outContent));
    }

    @After
    public void tearDown() {
        System.setOut(originalOut);
    }

    // Tests for authenticateUser method

    @Test
    public void testAuthenticateUser_WithSQLInjection() {
        // Test demonstrates SQL injection vulnerability
        // This test expects false due to connection failure, but the vulnerability exists
        boolean result = auth.authenticateUser("admin' OR '1'='1'; --", "anyPassword");
        // Note: This will return false due to connection issues, but demonstrates the vulnerability
        assertFalse("SQL injection attempt returns false due to connection failure", result);
    }

    @Test
    public void testAuthenticateUser_WithNormalCredentials() {
        // Test with normal credentials - expects false due to no DB connection
        boolean result = auth.authenticateUser("normalUser", "normalPassword");
        assertFalse("Authentication fails without database connection", result);
    }

    @Test
    public void testAuthenticateUser_WithEmptyUsername() {
        // Test edge case: empty username
        boolean result = auth.authenticateUser("", "password");
        assertFalse("Empty username should fail authentication", result);
    }

    @Test
    public void testAuthenticateUser_WithEmptyPassword() {
        // Test edge case: empty password
        boolean result = auth.authenticateUser("username", "");
        assertFalse("Empty password should fail authentication", result);
    }

    @Test
    public void testAuthenticateUser_WithNullUsername() {
        // Test edge case: null username
        boolean result = auth.authenticateUser(null, "password");
        assertFalse("Null username should fail authentication", result);
    }

    @Test
    public void testAuthenticateUser_WithNullPassword() {
        // Test edge case: null password
        boolean result = auth.authenticateUser("username", null);
        assertFalse("Null password should fail authentication", result);
    }

    @Test
    public void testAuthenticateUser_WithSpecialCharacters() {
        // Test with special characters that could cause SQL injection
        boolean result = auth.authenticateUser("user'; DROP TABLE users; --", "password");
        assertFalse("SQL injection with DROP statement should fail", result);
    }

    // Tests for processUserData method

    @Test
    public void testProcessUserData_WithNormalData() {
        // Test normal data processing
        auth.processUserData("Normal user data");
        // Method doesn't return anything, just verify no exception is thrown
        assertTrue("Processing normal data should complete without exception", true);
    }

    @Test
    public void testProcessUserData_WithEmptyString() {
        // Test edge case: empty string
        auth.processUserData("");
        assertTrue("Processing empty string should complete without exception", true);
    }

    @Test
    public void testProcessUserData_WithLargeData() {
        // Test with large data string
        StringBuilder largeData = new StringBuilder();
        for (int i = 0; i < 10000; i++) {
            largeData.append("data");
        }
        auth.processUserData(largeData.toString());
        assertTrue("Processing large data should complete without exception", true);
    }

    @Test
    public void testProcessUserData_WithSpecialCharacters() {
        // Test with special characters
        auth.processUserData("Data with special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?");
        assertTrue("Processing special characters should complete without exception", true);
    }

    // Tests for getUsername method

    @Test(expected = NullPointerException.class)
    public void testGetUsername_ThrowsNullPointerException() {
        // Test demonstrates NullPointerException vulnerability (username is always null)
        auth.getUsername(1);
    }

    @Test(expected = NullPointerException.class)
    public void testGetUsername_WithZeroUserId() {
        // Test edge case: zero user ID
        auth.getUsername(0);
    }

    @Test(expected = NullPointerException.class)
    public void testGetUsername_WithNegativeUserId() {
        // Test edge case: negative user ID
        auth.getUsername(-1);
    }

    @Test(expected = NullPointerException.class)
    public void testGetUsername_WithLargeUserId() {
        // Test edge case: very large user ID
        auth.getUsername(Integer.MAX_VALUE);
    }

    // Tests for addNumbers method

    @Test
    public void testAddNumbers_WithPositiveNumbers() {
        // Test normal addition
        int result = auth.addNumbers(5, 7);
        assertEquals("5 + 7 should equal 12", 12, result);
    }

    @Test
    public void testAddNumbers_WithZero() {
        // Test edge case: adding zero
        int result = auth.addNumbers(0, 5);
        assertEquals("0 + 5 should equal 5", 5, result);
    }

    @Test
    public void testAddNumbers_WithNegativeNumbers() {
        // Test with negative numbers
        int result = auth.addNumbers(-5, -3);
        assertEquals("-5 + -3 should equal -8", -8, result);
    }

    @Test
    public void testAddNumbers_WithMixedSigns() {
        // Test with mixed positive and negative
        int result = auth.addNumbers(10, -3);
        assertEquals("10 + -3 should equal 7", 7, result);
    }

    @Test
    public void testAddNumbers_WithOverflow() {
        // Test overflow behavior
        int result = auth.addNumbers(Integer.MAX_VALUE, 1);
        assertEquals("Integer overflow wraps to minimum", Integer.MIN_VALUE, result);
    }

    @Test
    public void testAddNumbers_BothZero() {
        // Test edge case: both zeros
        int result = auth.addNumbers(0, 0);
        assertEquals("0 + 0 should equal 0", 0, result);
    }

    @Test
    public void testAddNumbers_LargePositiveNumbers() {
        // Test with large positive numbers
        int result = auth.addNumbers(1000000, 2000000);
        assertEquals("1000000 + 2000000 should equal 3000000", 3000000, result);
    }

    // Tests for retrieveSensitiveInfo method

    @Test
    public void testRetrieveSensitiveInfo_WithValidUserId() {
        // Test retrieval of sensitive information
        String result = auth.retrieveSensitiveInfo(1);
        assertEquals("Should return sensitive info for user 1",
                     "Sensitive information for user 1", result);
    }

    @Test
    public void testRetrieveSensitiveInfo_WithZeroUserId() {
        // Test edge case: zero user ID
        String result = auth.retrieveSensitiveInfo(0);
        assertEquals("Should return sensitive info for user 0",
                     "Sensitive information for user 0", result);
    }

    @Test
    public void testRetrieveSensitiveInfo_WithNegativeUserId() {
        // Test edge case: negative user ID (no access control)
        String result = auth.retrieveSensitiveInfo(-1);
        assertEquals("Should return sensitive info for user -1",
                     "Sensitive information for user -1", result);
    }

    @Test
    public void testRetrieveSensitiveInfo_WithLargeUserId() {
        // Test edge case: large user ID
        String result = auth.retrieveSensitiveInfo(999999);
        assertEquals("Should return sensitive info for user 999999",
                     "Sensitive information for user 999999", result);
    }

    @Test
    public void testRetrieveSensitiveInfo_NoAccessControl() {
        // Test demonstrates lack of access control - any ID works
        String result1 = auth.retrieveSensitiveInfo(1);
        String result2 = auth.retrieveSensitiveInfo(2);
        assertNotNull("Should return info without access control check", result1);
        assertNotNull("Should return info without access control check", result2);
        assertNotEquals("Different user IDs should return different info", result1, result2);
    }

    // Tests for sendDataOverInsecureChannel method

    @Test
    public void testSendDataOverInsecureChannel_WithSensitiveData() {
        // Test sending sensitive data over insecure channel
        auth.sendDataOverInsecureChannel("Confidential data");
        String output = outContent.toString();
        assertTrue("Output should contain the sent data",
                   output.contains("Data sent over insecure channel: Confidential data"));
    }

    @Test
    public void testSendDataOverInsecureChannel_WithEmptyData() {
        // Test edge case: empty data
        auth.sendDataOverInsecureChannel("");
        String output = outContent.toString();
        assertTrue("Should handle empty data",
                   output.contains("Data sent over insecure channel: "));
    }

    @Test
    public void testSendDataOverInsecureChannel_WithSpecialCharacters() {
        // Test with special characters
        auth.sendDataOverInsecureChannel("Data with <script>alert('xss')</script>");
        String output = outContent.toString();
        assertTrue("Should send data with special characters",
                   output.contains("<script>"));
    }

    // Tests for inadequatePasswordHashing method

    @Test
    public void testInadequatePasswordHashing_WithNormalPassword() {
        // Test MD5 hashing of a normal password
        String result = auth.inadequatePasswordHashing("password123");
        assertNotNull("Hashed password should not be null", result);
        assertEquals("MD5 hash should be consistent",
                     "482C811DA5D5B4BC6D497FFA98491E38", result);
    }

    @Test
    public void testInadequatePasswordHashing_WithEmptyPassword() {
        // Test edge case: empty password
        String result = auth.inadequatePasswordHashing("");
        assertNotNull("Empty password hash should not be null", result);
        assertEquals("MD5 of empty string", "D41D8CD98F00B204E9800998ECF8427E", result);
    }

    @Test
    public void testInadequatePasswordHashing_Consistency() {
        // Test that same password produces same hash
        String hash1 = auth.inadequatePasswordHashing("testPassword");
        String hash2 = auth.inadequatePasswordHashing("testPassword");
        assertEquals("Same password should produce same hash", hash1, hash2);
    }

    @Test
    public void testInadequatePasswordHashing_WithSpecialCharacters() {
        // Test with special characters
        String result = auth.inadequatePasswordHashing("p@ssw0rd!#$");
        assertNotNull("Hash with special characters should not be null", result);
        assertTrue("Hash should be non-empty", result.length() > 0);
    }

    @Test
    public void testInadequatePasswordHashing_WithLongPassword() {
        // Test with very long password
        StringBuilder longPassword = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            longPassword.append("a");
        }
        String result = auth.inadequatePasswordHashing(longPassword.toString());
        assertNotNull("Long password hash should not be null", result);
        assertEquals("MD5 hash length should be 32 characters", 32, result.length());
    }

    @Test
    public void testInadequatePasswordHashing_DifferentPasswordsDifferentHashes() {
        // Test that different passwords produce different hashes
        String hash1 = auth.inadequatePasswordHashing("password1");
        String hash2 = auth.inadequatePasswordHashing("password2");
        assertNotEquals("Different passwords should produce different hashes", hash1, hash2);
    }

    @Test
    public void testInadequatePasswordHashing_VulnerabilityToCollisions() {
        // Test demonstrates weak MD5 algorithm (known vulnerability)
        // MD5 is cryptographically broken and should not be used for passwords
        String result = auth.inadequatePasswordHashing("password");
        assertNotNull("MD5 produces a hash, but is insecure", result);
        // This test passes but highlights the security issue
    }
}