-- ============================================================
-- MovieHub - Movie Rental System Database Schema v1.0.0
-- Target database: moviehub_db
--
-- Converted from: bike_rental_system (Bike Rental System)
-- Source database is READ-ONLY and is never modified.
--
-- Reused tables (same structure): users, admin_users, permissions,
--   role_permissions, user_permissions, account_status_history,
--   registration_approvals, deletion_requests, login_logs,
--   otp_codes, secret_questions, security_answers, audit_logs,
--   activity_logs
-- Replaced tables:
--   bikes           -> movies (+ new genres lookup table)
--   rental_requests -> rentals
-- ============================================================

CREATE DATABASE IF NOT EXISTS moviehub_db DEFAULT CHARSET utf8mb4 COLLATE utf8mb4_general_ci;
USE moviehub_db;

-- ============================================================
-- 1. REUSED TABLES (identical structure to bike_rental_system)
-- ============================================================

CREATE TABLE IF NOT EXISTS users (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    id_number VARCHAR(9) NOT NULL,
    employee_id VARCHAR(20) DEFAULT NULL,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    account_status ENUM('pending','approved','rejected','blocked','inactive','online','offline') NOT NULL DEFAULT 'pending',
    role ENUM('user','admin','super_admin') NOT NULL DEFAULT 'user',
    password VARCHAR(255) NOT NULL,
    first_name VARCHAR(50) DEFAULT NULL,
    middle_initial CHAR(1) DEFAULT NULL,
    last_name VARCHAR(50) DEFAULT NULL,
    extension_name VARCHAR(10) DEFAULT NULL,
    sex ENUM('Male','Female','Prefer not to say') DEFAULT NULL,
    birthdate DATE DEFAULT NULL,
    contact_number VARCHAR(20) DEFAULT NULL,
    security_question VARCHAR(255) DEFAULT NULL,
    security_answer_hash VARCHAR(255) DEFAULT NULL,
    must_change_password TINYINT(1) NOT NULL DEFAULT 0,
    last_login DATETIME DEFAULT NULL,
    address_street VARCHAR(100) DEFAULT NULL,
    address_barangay VARCHAR(100) DEFAULT NULL,
    address_city VARCHAR(100) DEFAULT NULL,
    address_province VARCHAR(100) DEFAULT NULL,
    address_country VARCHAR(100) DEFAULT NULL,
    zip_code VARCHAR(10) DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    profile_picture VARCHAR(255) DEFAULT NULL,
    is_deleted TINYINT(1) NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    UNIQUE KEY id_number (id_number),
    UNIQUE KEY username (username),
    UNIQUE KEY email (email),
    UNIQUE KEY employee_id (employee_id),
    KEY idx_users_account_status (account_status),
    KEY idx_users_role (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS admin_users (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    first_name VARCHAR(50) DEFAULT NULL,
    middle_initial CHAR(1) DEFAULT NULL,
    last_name VARCHAR(50) DEFAULT NULL,
    sex ENUM('Male','Female','Prefer not to say') DEFAULT NULL,
    birthdate DATE DEFAULT NULL,
    contact_number VARCHAR(20) DEFAULT NULL,
    role ENUM('admin','super_admin') NOT NULL DEFAULT 'admin',
    account_status ENUM('active','blocked','inactive') NOT NULL DEFAULT 'active',
    must_change_password TINYINT(1) NOT NULL DEFAULT 0,
    last_login DATETIME DEFAULT NULL,
    employee_id VARCHAR(20) DEFAULT NULL,
    id_number VARCHAR(20) DEFAULT NULL,
    is_deleted TINYINT(1) NOT NULL DEFAULT 0,
    profile_picture VARCHAR(255) DEFAULT NULL,
    phone VARCHAR(20) DEFAULT NULL,
    address TEXT DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY username (username),
    UNIQUE KEY email (email),
    UNIQUE KEY employee_id (employee_id),
    UNIQUE KEY id_number (id_number),
    KEY idx_admin_account_status (account_status),
    KEY idx_admin_role (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS pending_admin_accounts (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    id_number VARCHAR(20) DEFAULT NULL,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    role ENUM('admin','super_admin') NOT NULL DEFAULT 'admin',
    phone VARCHAR(20) DEFAULT NULL,
    created_by_admin_id INT UNSIGNED DEFAULT NULL,
    created_by_name VARCHAR(100) DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_pending_username (username),
    UNIQUE KEY uq_pending_email (email),
    UNIQUE KEY uq_pending_id_number (id_number)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS pending_user_accounts (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    id_number VARCHAR(20) DEFAULT NULL,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    created_by_admin_id INT UNSIGNED DEFAULT NULL,
    created_by_name VARCHAR(100) DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_pending_user_username (username),
    UNIQUE KEY uq_pending_user_email (email),
    UNIQUE KEY uq_pending_user_id_number (id_number)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS permissions (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    permission_key VARCHAR(100) UNIQUE NOT NULL,
    description VARCHAR(255) DEFAULT NULL,
    category VARCHAR(50) DEFAULT 'general',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS role_permissions (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    role ENUM('user','admin','super_admin') NOT NULL,
    permission_id INT UNSIGNED NOT NULL,
    granted TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_role_perm (role, permission_id),
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS user_permissions (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_table ENUM('users','admin_users') NOT NULL,
    user_id INT UNSIGNED NOT NULL,
    permission_id INT UNSIGNED NOT NULL,
    granted TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_user_perm (user_table, user_id, permission_id),
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS account_status_history (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_table ENUM('users','admin_users') NOT NULL,
    user_id INT UNSIGNED NOT NULL,
    old_status VARCHAR(20) DEFAULT NULL,
    new_status VARCHAR(20) NOT NULL,
    reason TEXT DEFAULT NULL,
    changed_by_table ENUM('users','admin_users') DEFAULT NULL,
    changed_by_id INT UNSIGNED DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user (user_table, user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS registration_approvals (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NOT NULL,
    status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
    reviewed_by_table VARCHAR(20) DEFAULT NULL,
    reviewed_by_id INT UNSIGNED DEFAULT NULL,
    rejection_reason TEXT DEFAULT NULL,
    reviewed_at TIMESTAMP NULL DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS deletion_requests (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    target_table ENUM('users','admin_users') NOT NULL,
    target_id INT UNSIGNED NOT NULL,
    target_name VARCHAR(150) DEFAULT NULL,
    target_email VARCHAR(100) DEFAULT NULL,
    target_role VARCHAR(20) DEFAULT NULL,
    requested_by_table ENUM('admin_users') NOT NULL,
    requested_by_id INT UNSIGNED NOT NULL,
    requested_by_name VARCHAR(100) DEFAULT NULL,
    requested_by_employee_id VARCHAR(20) DEFAULT NULL,
    reason TEXT NOT NULL,
    status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
    reviewed_by_id INT UNSIGNED DEFAULT NULL,
    reviewed_by_name VARCHAR(100) DEFAULT NULL,
    rejection_reason TEXT DEFAULT NULL,
    reviewed_at TIMESTAMP NULL DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS login_logs (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_table ENUM('users','admin_users') NOT NULL,
    user_id INT UNSIGNED NOT NULL,
    employee_id VARCHAR(20) DEFAULT NULL,
    full_name VARCHAR(100) DEFAULT NULL,
    username VARCHAR(50) NOT NULL,
    role VARCHAR(20) NOT NULL,
    action ENUM('login','logout') NOT NULL,
    status ENUM('success','failed','blocked') NOT NULL DEFAULT 'success',
    ip_address VARCHAR(45) DEFAULT NULL,
    user_agent TEXT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user (user_table, user_id),
    INDEX idx_created (created_at),
    INDEX idx_role (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS otp_codes (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_table ENUM('users','admin_users') NOT NULL,
    user_id INT UNSIGNED NOT NULL,
    otp_hash VARCHAR(255) NOT NULL,
    purpose ENUM('password_reset','verification','login') NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used TINYINT(1) NOT NULL DEFAULT 0,
    attempts INT UNSIGNED NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user (user_table, user_id),
    INDEX idx_purpose (purpose),
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS secret_questions (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    question_text VARCHAR(255) NOT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    sort_order INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS security_answers (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_table ENUM('users','admin_users') NOT NULL,
    user_id INT UNSIGNED NOT NULL,
    question_id INT UNSIGNED NOT NULL,
    answer_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_user_question (user_table, user_id, question_id),
    FOREIGN KEY (question_id) REFERENCES secret_questions(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS audit_logs (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    actor_table ENUM('users','admin_users') DEFAULT NULL,
    actor_id INT UNSIGNED DEFAULT NULL,
    actor_name VARCHAR(100) DEFAULT NULL,
    actor_role VARCHAR(20) DEFAULT NULL,
    action VARCHAR(100) NOT NULL,
    target_table VARCHAR(30) DEFAULT NULL,
    target_id INT UNSIGNED DEFAULT NULL,
    target_name VARCHAR(100) DEFAULT NULL,
    details TEXT DEFAULT NULL,
    ip_address VARCHAR(45) DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_actor (actor_table, actor_id),
    INDEX idx_action (action),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS activity_logs (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    admin_id INT NOT NULL,
    admin_username VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    target_type VARCHAR(50) NOT NULL,
    target_id INT NOT NULL,
    target_name VARCHAR(100) NOT NULL,
    reason TEXT DEFAULT NULL,
    ip_address VARCHAR(45) DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_admin (admin_id),
    INDEX idx_action (action)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- 2. NEW MOVIE-SPECIFIC TABLES
-- ============================================================

-- Genres lookup table (replaces free-text bikes.type)
CREATE TABLE IF NOT EXISTS genres (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Movies catalog (replaces bikes)
CREATE TABLE IF NOT EXISTS movies (
    movie_id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    title VARCHAR(150) NOT NULL,
    description TEXT DEFAULT NULL,
    genre_id INT UNSIGNED DEFAULT NULL,
    release_year SMALLINT UNSIGNED DEFAULT NULL,
    director VARCHAR(100) DEFAULT NULL,
    cast_members TEXT DEFAULT NULL,
    duration_minutes SMALLINT UNSIGNED DEFAULT NULL,
    rating DECIMAL(3,1) UNSIGNED DEFAULT NULL,
    rental_price DECIMAL(10,2) NOT NULL,
    poster VARCHAR(255) DEFAULT NULL,
    status ENUM('available','rented','maintenance') NOT NULL DEFAULT 'available',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (movie_id),
    KEY fk_movies_genre (genre_id),
    KEY idx_movies_status (status),
    CONSTRAINT fk_movies_genre FOREIGN KEY (genre_id) REFERENCES genres(id)
        ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Rentals (replaces rental_requests; same approval workflow)
CREATE TABLE IF NOT EXISTS rentals (
    rental_id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id INT UNSIGNED NOT NULL,
    movie_id INT UNSIGNED NOT NULL,
    status ENUM('pending','approved','denied') NOT NULL DEFAULT 'pending',
    rental_date DATE DEFAULT NULL,
    due_date DATE DEFAULT NULL,
    returned_at DATETIME DEFAULT NULL,
    rental_price DECIMAL(10,2) DEFAULT NULL,
    admin_notes TEXT DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (rental_id),
    KEY fk_rental_user (user_id),
    KEY fk_rental_movie (movie_id),
    KEY idx_rental_status (status),
    CONSTRAINT fk_rental_user FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_rental_movie FOREIGN KEY (movie_id) REFERENCES movies(movie_id)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ============================================================
-- 3. MIGRATE REUSABLE DATA FROM bike_rental_system (READ-ONLY)
--    Safe to re-run only on an empty database.
-- ============================================================

INSERT INTO users (id, id_number, employee_id, username, email, account_status, role, password, first_name, middle_initial, last_name, extension_name, sex, birthdate, contact_number, security_question, security_answer_hash, address_street, address_barangay, address_city, address_province, address_country, zip_code, created_at, updated_at, profile_picture, is_deleted)
SELECT id, id_number, employee_id, username, email, account_status, role, password, first_name, middle_initial, last_name, extension_name, sex, birthdate, contact_number, security_question, security_answer_hash, address_street, address_barangay, address_city, address_province, address_country, zip_code, created_at, updated_at, profile_picture, is_deleted
FROM bike_rental_system.users;

INSERT INTO admin_users (id, username, email, password, full_name, role, account_status, employee_id, is_deleted, profile_picture, phone, address, created_at)
SELECT id, username, email, password, full_name, role, account_status, employee_id, is_deleted, profile_picture, phone, address, created_at
FROM bike_rental_system.admin_users;

INSERT INTO permissions (id, permission_key, description, category, created_at)
SELECT id, permission_key, description, category, created_at
FROM bike_rental_system.permissions;

INSERT INTO role_permissions (id, role, permission_id, granted, created_at)
SELECT id, role, permission_id, granted, created_at
FROM bike_rental_system.role_permissions;

INSERT INTO user_permissions (id, user_table, user_id, permission_id, granted, created_at)
SELECT id, user_table, user_id, permission_id, granted, created_at
FROM bike_rental_system.user_permissions;

INSERT INTO account_status_history (id, user_table, user_id, old_status, new_status, reason, changed_by_table, changed_by_id, created_at)
SELECT id, user_table, user_id, old_status, new_status, reason, changed_by_table, changed_by_id, created_at
FROM bike_rental_system.account_status_history;

INSERT INTO registration_approvals (id, user_id, status, reviewed_by_table, reviewed_by_id, rejection_reason, reviewed_at, created_at)
SELECT id, user_id, status, reviewed_by_table, reviewed_by_id, rejection_reason, reviewed_at, created_at
FROM bike_rental_system.registration_approvals;

INSERT INTO deletion_requests (id, target_table, target_id, target_name, target_email, target_role, requested_by_table, requested_by_id, requested_by_name, requested_by_employee_id, reason, status, reviewed_by_id, reviewed_by_name, rejection_reason, reviewed_at, created_at)
SELECT id, target_table, target_id, target_name, target_email, target_role, requested_by_table, requested_by_id, requested_by_name, requested_by_employee_id, reason, status, reviewed_by_id, reviewed_by_name, rejection_reason, reviewed_at, created_at
FROM bike_rental_system.deletion_requests;

INSERT INTO login_logs (id, user_table, user_id, employee_id, full_name, username, role, action, status, ip_address, user_agent, created_at)
SELECT id, user_table, user_id, employee_id, full_name, username, role, action, status, ip_address, user_agent, created_at
FROM bike_rental_system.login_logs;

INSERT INTO otp_codes (id, user_table, user_id, otp_hash, purpose, expires_at, used, attempts, created_at)
SELECT id, user_table, user_id, otp_hash, purpose, expires_at, used, attempts, created_at
FROM bike_rental_system.otp_codes;

INSERT INTO secret_questions (id, question_text, is_active, sort_order, created_at)
SELECT id, question_text, is_active, sort_order, created_at
FROM bike_rental_system.secret_questions
WHERE id IN (1, 2, 3);

UPDATE secret_questions SET is_active = IF(id IN (1, 2, 3), 1, 0);

INSERT INTO security_answers (id, user_table, user_id, question_id, answer_hash, created_at)
SELECT id, user_table, user_id, question_id, answer_hash, created_at
FROM bike_rental_system.security_answers;

INSERT INTO audit_logs (id, actor_table, actor_id, actor_name, actor_role, action, target_table, target_id, target_name, details, ip_address, created_at)
SELECT id, actor_table, actor_id, actor_name, actor_role, action, target_table, target_id, target_name, details, ip_address, created_at
FROM bike_rental_system.audit_logs;

INSERT INTO activity_logs (id, admin_id, admin_username, action, target_type, target_id, target_name, reason, ip_address, created_at)
SELECT id, admin_id, admin_username, action, target_type, target_id, target_name, reason, ip_address, created_at
FROM bike_rental_system.activity_logs;

-- ============================================================
-- 4. RENAME BIKE PERMISSION KEYS TO MOVIE EQUIVALENTS
--    (IDs preserved so role_permissions / user_permissions stay valid)
-- ============================================================

UPDATE permissions SET permission_key = 'movies.view',   description = 'View movies',             category = 'movies' WHERE permission_key = 'bikes.view';
UPDATE permissions SET permission_key = 'movies.create', description = 'Create movies',           category = 'movies' WHERE permission_key = 'bikes.create';
UPDATE permissions SET permission_key = 'movies.update', description = 'Update movies',           category = 'movies' WHERE permission_key = 'bikes.update';
UPDATE permissions SET permission_key = 'movies.delete', description = 'Delete movies',           category = 'movies' WHERE permission_key = 'bikes.delete';

-- ============================================================
-- 5. SEED GENRES AND SAMPLE MOVIES
-- ============================================================

INSERT INTO genres (name) VALUES
('Action'), ('Adventure'), ('Animation'), ('Comedy'), ('Crime'),
('Documentary'), ('Drama'), ('Family'), ('Fantasy'), ('Horror'),
('Musical'), ('Mystery'), ('Romance'), ('Sci-Fi'), ('Thriller'),
('War'), ('Western');

INSERT INTO movies (title, description, genre_id, release_year, director, cast_members, duration_minutes, rating, rental_price, poster, status) VALUES
('The Midnight Odyssey', 'A deep-space crew answers a distress signal from a ship that vanished decades ago.', (SELECT id FROM genres WHERE name='Sci-Fi'), 2019, 'Elena Cruz', 'Marco Reyes, Ana Villanueva, Josh Tan', 128, 8.2, 45.00, NULL, 'available'),
('City of Echoes', 'A detective hunts a serial thief through a city where every wall remembers.', (SELECT id FROM genres WHERE name='Crime'), 2021, 'Ramon Dela Peña', 'Liza Soberano, John Arcilla, Mia Torres', 112, 7.6, 40.00, NULL, 'available'),
('Paper Hearts', 'Two rival bookstore owners are forced to co-host the town reading festival.', (SELECT id FROM genres WHERE name='Romance'), 2020, 'Sofia Mendoza', 'Bea Alonzo, Gerald Anderson', 104, 7.1, 35.00, NULL, 'available'),
('The Last Lighthouse', 'A storm traps a keeper and a stranger with a dangerous secret.', (SELECT id FROM genres WHERE name='Thriller'), 2022, 'Victor Lim', 'Piolo Pascual, Coleen Garcia', 119, 7.9, 50.00, NULL, 'available');

-- ============================================================
-- 6. DONE
-- ============================================================
SELECT 'MovieHub database (moviehub_db) created successfully!' AS result;
