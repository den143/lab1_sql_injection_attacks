package com.ias101.lab1.security;

import com.ias101.lab1.database.util.DBUtil;
import com.ias101.lab1.model.User;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class Authenticator {
    private static final Pattern ALLOWED_PATTERN = Pattern.compile("^[a-zA-Z0-9]+$");

    public static boolean authenticateUser(String username, String password) {
        if (!isValidInput(username) || !isValidInput(password)) {
            System.err.println("Invalid input: Special characters are not allowed.");
            return false;
        }

        String query = "SELECT * FROM user_data WHERE username = ? AND password = ?";

        try (Connection conn = DBUtil.connect("jdbc:sqlite:src/main/resources/database/sample.db", "root", "root");
             PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setString(1, username);
            stmt.setString(2, password);

            ResultSet rs = stmt.executeQuery();
            return rs.next();
        } catch (SQLException e) {
            System.err.println("Database error during authentication: " + e.getMessage());
            return false;
        }
    }

    private static boolean isValidInput(String input) {
        return ALLOWED_PATTERN.matcher(input).matches();
    }

    public static List<User> getAll() {
        List<User> users = new ArrayList<>();
        String query = "SELECT * FROM user_data";

        try (Connection connection = DBUtil.connect("jdbc:sqlite:src/main/resources/database/sample.db", "root", "root");
             PreparedStatement stmt = connection.prepareStatement(query);
             ResultSet rs = stmt.executeQuery()) {

            while (rs.next()) {
                users.add(new User(rs.getString("username"), rs.getString("password")));
            }
        } catch (SQLException e) {
            System.err.println("Error fetching users: " + e.getMessage());
        }
        return users;
    }

    public static User searchByUsername(String username) {
        if (!isValidInput(username)) {
            System.err.println("Invalid input: Special characters are not allowed.");
            return null;
        }

        String query = "SELECT * FROM user_data WHERE username = ?";

        try (Connection connection = DBUtil.connect("jdbc:sqlite:src/main/resources/database/sample.db", "root", "root");
             PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                return new User(rs.getString("username"), rs.getString("password"));
            }
        } catch (SQLException e) {
            System.err.println("Error searching for user: " + e.getMessage());
        }
        return null;
    }

    public static void deleteUserByUsername(String username) {
        if (!isValidInput(username)) {
            System.err.println("Invalid input: Special characters are not allowed.");
            return;
        }

        String query = "DELETE FROM user_data WHERE username = ?";

        try (Connection connection = DBUtil.connect("jdbc:sqlite:src/main/resources/database/sample.db", "root", "root");
             PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, username);
            stmt.executeUpdate();
            System.out.printf("User '%s' has been deleted.%n", username);
        } catch (SQLException e) {
            System.err.println("Error deleting user: " + e.getMessage());
        }
    }
}
