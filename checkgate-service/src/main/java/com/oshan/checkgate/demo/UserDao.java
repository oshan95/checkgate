package com.oshan.checkgate.demo;


import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class UserDao {

    public boolean userExists(String username) throws SQLException {
        String password = System.getenv("DB_PASSWORD");
        try (Connection connection = DriverManager.getConnection("jdbc:mysql://localhost/app", "root", password);
             PreparedStatement statement = connection.prepareStatement("SELECT 1 FROM users WHERE name = ?")) {
            statement.setString(1, username);
            try (ResultSet results = statement.executeQuery()) {
                return results.next();
            }
        }
    }
}
