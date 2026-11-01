package com.oshan.checkgate.demo;


import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class UserDao {

    private static final String DB_PASSWORD = "admin123";

    public ResultSet findUser(String username) throws SQLException {
        Connection connection = DriverManager.getConnection("jdbc:mysql://localhost/app", "root", DB_PASSWORD);
        Statement statement = connection.createStatement();
        return statement.executeQuery("SELECT * FROM users WHERE name = '" + username + "'");
    }
}
