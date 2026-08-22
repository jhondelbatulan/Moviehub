-- Bike Rental System Database Schema
-- Run this SQL script in phpMyAdmin to create the database and tables

CREATE DATABASE IF NOT EXISTS bike_rental_system;
USE bike_rental_system;

-- Users table for client accounts
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    id_number VARCHAR(9) UNIQUE NOT NULL,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    first_name VARCHAR(50) NOT NULL,
    middle_initial CHAR(1),
    last_name VARCHAR(50) NOT NULL,
    extension_name VARCHAR(10),
    sex ENUM('Male','Female','Prefer not to say') NOT NULL,
    birthdate DATE NOT NULL,
    age TINYINT UNSIGNED GENERATED ALWAYS AS (TIMESTAMPDIFF(YEAR, birthdate, CURRENT_DATE)) STORED,
    contact_number VARCHAR(20) NOT NULL,
    security_question VARCHAR(255) NOT NULL,
    security_answer_hash VARCHAR(255) NOT NULL,
    address_street VARCHAR(100),
    address_barangay VARCHAR(100),
    address_city VARCHAR(100),
    address_province VARCHAR(100),
    address_country VARCHAR(100),
    zip_code VARCHAR(10),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Admin users table
CREATE TABLE admin_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Bikes inventory table
CREATE TABLE bikes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    bike_name VARCHAR(100) NOT NULL,
    type VARCHAR(50) NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    image VARCHAR(255),
    availability ENUM('available', 'rented', 'maintenance') DEFAULT 'available',
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Rental requests table
CREATE TABLE rental_requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    bike_id INT NOT NULL,
    status ENUM('pending', 'approved', 'denied') DEFAULT 'pending',
    request_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    rental_start_date DATE,
    rental_end_date DATE,
    total_amount DECIMAL(10,2),
    admin_notes TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (bike_id) REFERENCES bikes(id) ON DELETE CASCADE
);

-- Insert default admin user (password: admin123)
INSERT INTO admin_users (username, email, password, full_name) VALUES 
('admin', 'admin@bikerental.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'System Administrator');

-- Insert sample bikes
INSERT INTO bikes (bike_name, type, price, image, description) VALUES 
('Mountain Pro', 'Mountain Bike', 25.00, 'mountain_pro.jpg', 'High-quality mountain bike perfect for off-road adventures'),
('City Cruiser', 'City Bike', 15.00, 'city_cruiser.jpg', 'Comfortable city bike for urban commuting'),
('Speed Demon', 'Road Bike', 30.00, 'speed_demon.jpg', 'Lightweight road bike for speed enthusiasts'),
('Family Bike', 'Hybrid Bike', 20.00, 'family_bike.jpg', 'Versatile hybrid bike suitable for all family members');
