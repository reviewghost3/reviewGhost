public class Main {
    public static void main(String[] args) {
        UserAuthentication auth = new UserAuthentication();

        
        boolean isAuthenticated = auth.authenticateUser("admin' OR '1'='1'; --", "maliciousPassword");
        System.out.println("Authentication Result: " + isAuthenticated);

        
        auth.processUserData("Sensitive user data");

        
        String username = auth.getUsername(1);
        System.out.println("Username: " + username);

        
        int sum = auth.addNumbers(5, 7);
        System.out.println("Sum: " + sum);

        
        String sensitiveInfo = auth.retrieveSensitiveInfo(1);
        System.out.println("Sensitive Information: " + sensitiveInfo);

        
        auth.sendDataOverInsecureChannel("Confidential data");

        
        String hashedPassword = auth.inadequatePasswordHashing("password123");
        System.out.println("Hashed Password: " + hashedPassword);
    }
}
