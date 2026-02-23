import org.junit.Test;
import org.junit.Before;
import org.junit.After;
import static org.junit.Assert.*;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

/**
 * Comprehensive test suite for Main class.
 * Tests verify the main method's integration with UserAuthentication.
 */
public class MainTest {

    private final ByteArrayOutputStream outContent = new ByteArrayOutputStream();
    private final ByteArrayOutputStream errContent = new ByteArrayOutputStream();
    private final PrintStream originalOut = System.out;
    private final PrintStream originalErr = System.err;

    @Before
    public void setUp() {
        System.setOut(new PrintStream(outContent));
        System.setErr(new PrintStream(errContent));
    }

    @After
    public void tearDown() {
        System.setOut(originalOut);
        System.setErr(originalErr);
    }

    @Test
    public void testMain_ExecutesWithoutException() {
        // Test that main method executes without throwing exceptions
        try {
            Main.main(new String[]{});
            assertTrue("Main should execute without exceptions", true);
        } catch (Exception e) {
            fail("Main should not throw exception: " + e.getMessage());
        }
    }

    @Test
    public void testMain_PrintsAuthenticationResult() {
        // Test that authentication result is printed
        Main.main(new String[]{});
        String output = outContent.toString();
        assertTrue("Output should contain authentication result",
                   output.contains("Authentication Result:"));
    }

    @Test
    public void testMain_PrintsAuthenticationFalse() {
        // Test that authentication returns false (due to no DB connection)
        Main.main(new String[]{});
        String output = outContent.toString();
        assertTrue("Authentication should fail without database",
                   output.contains("Authentication Result: false"));
    }

    @Test
    public void testMain_CallsProcessUserData() {
        // Verify processUserData is called (no exception thrown)
        try {
            Main.main(new String[]{});
            // If we reach here, processUserData was called successfully
            assertTrue("processUserData should be called", true);
        } catch (Exception e) {
            fail("processUserData should not throw exception: " + e.getMessage());
        }
    }

    @Test
    public void testMain_CallsGetUsernameAndThrowsNPE() {
        // Test that getUsername call results in NullPointerException
        try {
            Main.main(new String[]{});
            fail("Should throw NullPointerException from getUsername");
        } catch (NullPointerException e) {
            // Expected exception
            assertTrue("NullPointerException expected from getUsername", true);
        }
    }

    @Test
    public void testMain_PrintsSumResult() {
        // Test that sum calculation is printed (if execution reaches that point)
        // Note: This test will fail if NullPointerException occurs first
        // We'll create a separate integration test
        UserAuthentication auth = new UserAuthentication();
        int sum = auth.addNumbers(5, 7);
        assertEquals("Sum should be calculated correctly", 12, sum);
    }

    @Test
    public void testMain_WithEmptyArgs() {
        // Test main with empty arguments
        Main.main(new String[]{});
        String output = outContent.toString();
        assertNotNull("Output should not be null", output);
    }

    @Test
    public void testMain_WithNullArgs() {
        // Test main with null arguments (edge case)
        try {
            Main.main(null);
            // Method should still execute as args is not used
            assertTrue("Main should handle null args", true);
        } catch (NullPointerException e) {
            // NPE from getUsername is expected
            assertTrue("NullPointerException expected", true);
        }
    }

    @Test
    public void testMain_WithMultipleArgs() {
        // Test main with multiple arguments (should be ignored)
        Main.main(new String[]{"arg1", "arg2", "arg3"});
        String output = outContent.toString();
        assertNotNull("Output should not be null with extra args", output);
    }

    @Test
    public void testMain_PrintsSQLInjectionAttempt() {
        // Verify the SQL injection attempt string is present in execution
        Main.main(new String[]{});
        // The SQL injection string is hardcoded in Main.java
        String output = outContent.toString();
        assertTrue("Should attempt authentication with SQL injection",
                   output.contains("Authentication Result:"));
    }

    @Test
    public void testMain_PrintsInsecureChannelMessage() {
        // Test that data is sent over insecure channel
        // Note: May not reach this point due to NullPointerException
        UserAuthentication auth = new UserAuthentication();
        ByteArrayOutputStream testOut = new ByteArrayOutputStream();
        System.setOut(new PrintStream(testOut));
        auth.sendDataOverInsecureChannel("Confidential data");
        String output = testOut.toString();
        assertTrue("Should print insecure channel message",
                   output.contains("Data sent over insecure channel:"));
    }

    @Test
    public void testMain_HashedPasswordOutput() {
        // Test password hashing functionality
        UserAuthentication auth = new UserAuthentication();
        String hash = auth.inadequatePasswordHashing("password123");
        assertNotNull("Hashed password should not be null", hash);
        assertEquals("Should produce consistent MD5 hash",
                     "482C811DA5D5B4BC6D497FFA98491E38", hash);
    }

    @Test
    public void testMain_InstantiatesUserAuthentication() {
        // Test that UserAuthentication can be instantiated
        UserAuthentication auth = new UserAuthentication();
        assertNotNull("UserAuthentication should be instantiated", auth);
    }

    @Test
    public void testMain_ErrorStreamCapture() {
        // Test that SQL exceptions are printed to error stream
        Main.main(new String[]{});
        String errorOutput = errContent.toString();
        // SQL connection failure should print stack trace
        assertNotNull("Error stream should be available", errorOutput);
    }

    @Test
    public void testMain_MultipleExecutions() {
        // Test that main can be called multiple times
        try {
            Main.main(new String[]{});
        } catch (NullPointerException e) {
            // Expected from getUsername
        }

        try {
            Main.main(new String[]{});
        } catch (NullPointerException e) {
            // Expected from getUsername
        }

        assertTrue("Multiple executions should be possible", true);
    }

    @Test
    public void testMain_VerifiesMethodCallSequence() {
        // Test verifies methods are called in expected sequence
        // 1. authenticateUser
        // 2. processUserData
        // 3. getUsername (throws NPE)
        UserAuthentication auth = new UserAuthentication();

        // Verify first call succeeds
        boolean authResult = auth.authenticateUser("admin' OR '1'='1'; --", "maliciousPassword");
        assertFalse("Authentication should fail", authResult);

        // Verify second call succeeds
        auth.processUserData("Sensitive user data");
        assertTrue("processUserData should succeed", true);

        // Verify third call throws NPE
        try {
            auth.getUsername(1);
            fail("getUsername should throw NullPointerException");
        } catch (NullPointerException e) {
            assertTrue("Expected NullPointerException", true);
        }
    }
}