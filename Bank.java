import java.sql.*;
import java.util.Scanner;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.spec.KeySpec;

public class Bank {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        try {
            while (true) {
                // Main Menu
                System.out.println("\n Bank App ");
                System.out.println("1. Create Account");
                System.out.println("2. Login");
                System.out.println("3. Exit");
                System.out.print("Choose an option: ");
                String choice = scanner.nextLine();

                if (choice.equals("1")) {
                    createAccount(scanner); // Create new user account
                } else if (choice.equals("2")) {
                    login(scanner); // Login to account
                } else if (choice.equals("3")) {
                    System.out.println("Goodbye!");
                    break;
                } else {
                    System.out.println("Invalid option. Please try again.");
                }
            }
        } finally {
            scanner.close(); // Close scanner when done
        }
    }

    //  Create New Account 
    private static void createAccount(Scanner scanner) {
        try {
            // Get username
            System.out.print("Enter username (3-20 chars): ");
            String username = scanner.nextLine();
            if (username.length() < 3 || username.length() > 20) {
                System.out.println("Invalid username length!");
                return;
            }

            // Get email
            System.out.print("Enter email: ");
            String email = scanner.nextLine();
            if (!isValidEmail(email)) {
                System.out.println("Invalid email format!");
                return;
            }

            // Get password
            System.out.print("Enter password (min 6 chars): ");
            String password = scanner.nextLine();
            if (password.length() < 6) {
                System.out.println("Password too short!");
                return;
            }

            // Encrypt password with salt
            byte[] salt = generateSalt();
            byte[] encryptedPassword = getEncryptedPassword(password, salt);

            // Save user to database
            try {
                Class.forName("com.mysql.cj.jdbc.Driver");
                Connection conn = DriverManager.getConnection(
                        "jdbc:mysql://localhost:3306/bankdb", "root", "password");

                String sql = "INSERT INTO users (username, email, password, salt, balance) VALUES (?, ?, ?, ?, ?)";
                PreparedStatement pstmt = conn.prepareStatement(sql);
                pstmt.setString(1, username);
                pstmt.setString(2, email);
                pstmt.setBytes(3, encryptedPassword);
                pstmt.setBytes(4, salt);
                pstmt.setDouble(5, 0); // Start with £0 balance

                int rows = pstmt.executeUpdate();
                if (rows > 0) {
                    System.out.println("User registered successfully!");
                }

                conn.close();
            } catch (SQLException | ClassNotFoundException e) {
                System.out.println("Database error: " + e.getMessage());
            }

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    //  Check if email looks valid 
    private static boolean isValidEmail(String email) {
        return email.contains("@") && email.contains(".");
    }

    //  Login and OTP 
    private static void login(Scanner scanner) {
        try {
            System.out.print("Enter username: ");
            String username = scanner.nextLine();

            System.out.print("Enter password: ");
            String password = scanner.nextLine();

            try {
                Class.forName("com.mysql.cj.jdbc.Driver");
                Connection conn = DriverManager.getConnection(
                        "jdbc:mysql://localhost:3306/bankdb", "root", "password");

                String sql = "SELECT * FROM users WHERE username = ?";
                PreparedStatement pstmt = conn.prepareStatement(sql);
                pstmt.setString(1, username);
                ResultSet rs = pstmt.executeQuery();

                if (rs.next()) {
                    byte[] storedPasswordBytes = rs.getBytes("password");
                    byte[] salt = rs.getBytes("salt");

                    byte[] encryptedAttemptedPassword = getEncryptedPassword(password, salt);

                    // Check password
                    if (Arrays.equals(encryptedAttemptedPassword, storedPasswordBytes)) {
                        System.out.println("Login successful! Welcome " + username + "!");

                        // Generate OTP
                        String otp = generateOTP();
                        System.out.println("Your OTP is: " + otp);

                        System.out.print("Enter the OTP: ");
                        String enteredOtp = scanner.nextLine();

                        if (otp.equals(enteredOtp)) {
                            System.out.println("OTP verified. Access granted!");
                            bankOperations(scanner, conn, username);
                        } else {
                            System.out.println("Incorrect OTP. Access denied.");
                        }

                    } else {
                        System.out.println("Incorrect password!");
                    }

                } else {
                    System.out.println("Username not found!");
                }

                conn.close();
            } catch (SQLException | ClassNotFoundException e) {
                System.out.println("Database error: " + e.getMessage());
            }

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    //  Banking Menu 
    private static void bankOperations(Scanner scanner, Connection conn, String username) {
        try {
            while (true) {
                System.out.println("\n Bank Menu ");
                System.out.println("1. Check Balance");
                System.out.println("2. Deposit");
                System.out.println("3. Withdraw");
                System.out.println("4. Logout");
                System.out.print("Choose an option: ");
                String choice = scanner.nextLine();

                if (choice.equals("1")) {
                    checkBalance(conn, username); // Show balance
                } else if (choice.equals("2")) {
                    deposit(scanner, conn, username); // Add money
                } else if (choice.equals("3")) {
                    withdraw(scanner, conn, username); // Take out money
                } else if (choice.equals("4")) {
                    System.out.println("Logged out successfully. Goodbye "+username);
                    break;
                } else {
                    System.out.println("Invalid option. Please try again.");
                }
            }
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    //  Check Balance 
    private static void checkBalance(Connection conn, String username) throws SQLException {
        String sql = "SELECT balance FROM users WHERE username = ?";
        PreparedStatement pstmt = conn.prepareStatement(sql);
        pstmt.setString(1, username);
        ResultSet rs = pstmt.executeQuery();

        if (rs.next()) {
            double balance = rs.getDouble("balance");
            System.out.println("Your current balance is: £" + balance);
        } else {
            System.out.println("Error fetching balance.");
        }
    }

    //  Deposit Money 
    private static void deposit(Scanner scanner, Connection conn, String username) throws SQLException {
        System.out.print("Enter amount to deposit (£): ");
        double amount = Double.parseDouble(scanner.nextLine());

        if (amount <= 0) {
            System.out.println("Deposit amount must be positive.");
            return;
        }

        String sql = "UPDATE users SET balance = balance + ? WHERE username = ?";
        PreparedStatement pstmt = conn.prepareStatement(sql);
        pstmt.setDouble(1, amount);
        pstmt.setString(2, username);

        int rows = pstmt.executeUpdate();
        if (rows > 0) {
            double newBalance = getBalance(conn, username);
            System.out.println("Deposit successful! New balance is: £" + newBalance);
        } else {
            System.out.println("Error depositing amount.");
        }
    }

    //  Withdraw Money 
    private static void withdraw(Scanner scanner, Connection conn, String username) throws SQLException {
        System.out.print("Enter amount to withdraw (£): ");
        double amount = Double.parseDouble(scanner.nextLine());

        if (amount <= 0) {
            System.out.println("Withdrawal amount must be positive.");
            return;
        }

        double currentBalance = getBalance(conn, username);
        if (amount > currentBalance) {
            System.out.println("Insufficient balance.");
            return;
        }

        String sql = "UPDATE users SET balance = balance - ? WHERE username = ?";
        PreparedStatement pstmt = conn.prepareStatement(sql);
        pstmt.setDouble(1, amount);
        pstmt.setString(2, username);

        int rows = pstmt.executeUpdate();
        if (rows > 0) {
            System.out.println("Withdrawal successful! New balance is: £" + (currentBalance - amount));
        } else {
            System.out.println("Error withdrawing amount.");
        }
    }

    //  Get Balance Helper 
    private static double getBalance(Connection conn, String username) throws SQLException {
        String sql = "SELECT balance FROM users WHERE username = ?";
        PreparedStatement pstmt = conn.prepareStatement(sql);
        pstmt.setString(1, username);
        ResultSet rs = pstmt.executeQuery();

        if (rs.next()) {
            return rs.getDouble("balance");
        } else {
            return 0;
        }
    }

    //  Generate Salt (for password encryption) 
    public static byte[] generateSalt() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[8];
        random.nextBytes(salt);
        return salt;
    }

    // Encrypt Password
    public static byte[] getEncryptedPassword(String password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        String algorithm = "PBKDF2WithHmacSHA1";
        int derivedKeyLength = 160;
        int iterations = 20000;

        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, derivedKeyLength);
        SecretKeyFactory f = SecretKeyFactory.getInstance(algorithm);
        return f.generateSecret(spec).getEncoded();
    }

    // Generate secure 6-digit OTP
    public static String generateOTP() {
    SecureRandom random = new SecureRandom();
    int otp = 100000 + random.nextInt(900000);
    return String.valueOf(otp);
}

}
