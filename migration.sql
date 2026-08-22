-- ============================================================
-- Bike Rental System - Database Migration v3.0.0
-- Date: 2026-08-21
-- Description: 3-level RBAC, OTP, secret questions, login logs,
--              registration approval, deletion requests, audit,
--              privilege management, account blocking.
-- ============================================================
-- Safe to re-run (idempotent).
-- ============================================================

USE bike_rental_system;

-- ============================================================
-- 1. MODIFY EXISTING TABLES
-- ============================================================

-- users: add columns
SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='bike_rental_system' AND TABLE_NAME='users' AND COLUMN_NAME='account_status');
SET @sql = IF(@col=0, "ALTER TABLE users ADD COLUMN account_status ENUM('pending','approved','rejected','blocked') NOT NULL DEFAULT 'pending' AFTER email", 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='bike_rental_system' AND TABLE_NAME='users' AND COLUMN_NAME='role');
SET @sql = IF(@col=0, "ALTER TABLE users ADD COLUMN role ENUM('user','admin','super_admin') NOT NULL DEFAULT 'user' AFTER account_status", 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='bike_rental_system' AND TABLE_NAME='users' AND COLUMN_NAME='employee_id');
SET @sql = IF(@col=0, "ALTER TABLE users ADD COLUMN employee_id VARCHAR(20) UNIQUE DEFAULT NULL AFTER id_number", 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='bike_rental_system' AND TABLE_NAME='users' AND COLUMN_NAME='is_deleted');
SET @sql = IF(@col=0, "ALTER TABLE users ADD COLUMN is_deleted TINYINT(1) NOT NULL DEFAULT 0 AFTER zip_code", 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='bike_rental_system' AND TABLE_NAME='users' AND COLUMN_NAME='profile_picture');
SET @sql = IF(@col=0, "ALTER TABLE users ADD COLUMN profile_picture VARCHAR(255) DEFAULT NULL AFTER is_deleted", 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

-- admin_users: add columns
SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='bike_rental_system' AND TABLE_NAME='admin_users' AND COLUMN_NAME='account_status');
SET @sql = IF(@col=0, "ALTER TABLE admin_users ADD COLUMN account_status ENUM('active','blocked') NOT NULL DEFAULT 'active' AFTER password", 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='bike_rental_system' AND TABLE_NAME='admin_users' AND COLUMN_NAME='role');
SET @sql = IF(@col=0, "ALTER TABLE admin_users ADD COLUMN role ENUM('admin','super_admin') NOT NULL DEFAULT 'admin' AFTER account_status", 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='bike_rental_system' AND TABLE_NAME='admin_users' AND COLUMN_NAME='employee_id');
SET @sql = IF(@col=0, "ALTER TABLE admin_users ADD COLUMN employee_id VARCHAR(20) UNIQUE DEFAULT NULL AFTER full_name", 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='bike_rental_system' AND TABLE_NAME='admin_users' AND COLUMN_NAME='is_deleted');
SET @sql = IF(@col=0, "ALTER TABLE admin_users ADD COLUMN is_deleted TINYINT(1) NOT NULL DEFAULT 0 AFTER employee_id", 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='bike_rental_system' AND TABLE_NAME='admin_users' AND COLUMN_NAME='profile_picture');
SET @sql = IF(@col=0, "ALTER TABLE admin_users ADD COLUMN profile_picture VARCHAR(255) DEFAULT NULL AFTER is_deleted", 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='bike_rental_system' AND TABLE_NAME='admin_users' AND COLUMN_NAME='phone');
SET @sql = IF(@col=0, "ALTER TABLE admin_users ADD COLUMN phone VARCHAR(20) DEFAULT NULL AFTER profile_picture", 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='bike_rental_system' AND TABLE_NAME='admin_users' AND COLUMN_NAME='address');
SET @sql = IF(@col=0, "ALTER TABLE admin_users ADD COLUMN address TEXT DEFAULT NULL AFTER phone", 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

-- ============================================================
-- 2. DROP OLD VIEW (depends on old columns)
-- ============================================================
DROP VIEW IF EXISTS users_with_age;

-- ============================================================
-- 3. CREATE NEW TABLES
-- ============================================================

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

-- ============================================================
-- 4. SEED DATA
-- ============================================================

INSERT IGNORE INTO permissions (permission_key, description, category) VALUES
('dashboard.view', 'View dashboard', 'dashboard'),
('users.view', 'View users', 'users'),
('users.create', 'Create user accounts', 'users'),
('users.update', 'Update user accounts', 'users'),
('users.block', 'Block user accounts', 'users'),
('users.unblock', 'Unblock user accounts', 'users'),
('users.delete', 'Delete user accounts', 'users'),
('admins.view', 'View administrators', 'admins'),
('admins.create', 'Create administrator accounts', 'admins'),
('admins.update', 'Update administrator accounts', 'admins'),
('admins.block', 'Block administrator accounts', 'admins'),
('admins.unblock', 'Unblock administrator accounts', 'admins'),
('admins.delete', 'Delete administrator accounts', 'admins'),
('super_admins.view', 'View super administrators', 'super_admins'),
('super_admins.create', 'Create super admin accounts', 'super_admins'),
('super_admins.update', 'Update super admin accounts', 'super_admins'),
('bikes.view', 'View bikes', 'bikes'),
('bikes.create', 'Create bikes', 'bikes'),
('bikes.update', 'Update bikes', 'bikes'),
('bikes.delete', 'Delete bikes', 'bikes'),
('rentals.view', 'View rental requests', 'rentals'),
('rentals.approve', 'Approve rental requests', 'rentals'),
('rentals.reject', 'Reject rental requests', 'rentals'),
('registrations.view', 'View pending registrations', 'registrations'),
('registrations.approve', 'Approve registrations', 'registrations'),
('registrations.reject', 'Reject registrations', 'registrations'),
('logs.view', 'View own logs', 'logs'),
('logs.view_all', 'View all logs', 'logs'),
('privileges.view', 'View privileges', 'privileges'),
('privileges.assign', 'Assign privileges', 'privileges'),
('deletion_requests.view', 'View deletion requests', 'deletion_requests'),
('deletion_requests.approve', 'Approve deletion requests', 'deletion_requests'),
('deletion_requests.reject', 'Reject deletion requests', 'deletion_requests'),
('audit.view', 'View audit logs', 'audit'),
('account_management.view', 'View account management', 'account_management'),
('account_management.create', 'Create accounts', 'account_management'),
('account_management.update', 'Update accounts', 'account_management'),
('account_management.block', 'Block accounts', 'account_management'),
('account_management.unblock', 'Unblock accounts', 'account_management'),
('account_management.delete', 'Delete accounts', 'account_management');

-- super_admin gets ALL permissions
INSERT IGNORE INTO role_permissions (role, permission_id, granted)
SELECT 'super_admin', id, 1 FROM permissions;

-- admin gets limited permissions
INSERT IGNORE INTO role_permissions (role, permission_id, granted)
SELECT 'admin', id, 1 FROM permissions
WHERE permission_key IN (
    'dashboard.view', 'users.view', 'users.block', 'users.unblock', 'users.update',
    'bikes.view', 'bikes.create', 'bikes.update', 'bikes.delete',
    'rentals.view', 'rentals.approve', 'rentals.reject',
    'registrations.view', 'registrations.approve', 'registrations.reject',
    'logs.view', 'account_management.view', 'account_management.update',
    'account_management.block', 'account_management.unblock'
);

-- user gets basic permissions
INSERT IGNORE INTO role_permissions (role, permission_id, granted)
SELECT 'user', id, 1 FROM permissions
WHERE permission_key IN ('dashboard.view', 'bikes.view', 'rentals.view', 'logs.view');

-- Seed secret questions (15 questions)
INSERT IGNORE INTO secret_questions (id, question_text, sort_order) VALUES
(1, 'What was the name of your first pet?', 1),
(2, 'What is your favorite childhood place?', 2),
(3, 'What was the name of your first school?', 3),
(4, 'What is your mother''s maiden name?', 4),
(5, 'What city were you born in?', 5),
(6, 'What is your favorite food?', 6),
(7, 'What is your favorite movie?', 7),
(8, 'What is your favorite song?', 8),
(9, 'What is your favorite color?', 9),
(10, 'What was the make of your first car?', 10),
(11, 'What is your father''s middle name?', 11),
(12, 'What is your favorite sports team?', 12),
(13, 'What was the street you grew up on?', 13),
(14, 'Who is your best friend in Elementary?', 14),
(15, 'Who is your favorite teacher in high school?', 15);

-- ============================================================
-- 5. SET DEFAULTS FOR EXISTING DATA
-- ============================================================

-- Set existing admin user to super_admin
UPDATE admin_users SET role = 'super_admin', account_status = 'active'
WHERE username = 'admin' AND (role IS NULL OR role = '' OR role = 'admin');

-- Set existing client users to approved
UPDATE users SET account_status = 'approved'
WHERE account_status IS NULL OR account_status = 'pending';

-- Create registration approval records for existing approved users
INSERT IGNORE INTO registration_approvals (user_id, status, reviewed_at)
SELECT id, 'approved', NOW() FROM users WHERE account_status = 'approved';

-- ============================================================
-- 6. ADD INDEXES
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_users_account_status ON users(account_status);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_admin_account_status ON admin_users(account_status);
CREATE INDEX IF NOT EXISTS idx_admin_role ON admin_users(role);
CREATE INDEX IF NOT EXISTS idx_rental_status ON rental_requests(status);
CREATE INDEX IF NOT EXISTS idx_bikes_availability ON bikes(availability);

-- ============================================================
-- 7. DONE
-- ============================================================
SELECT 'Migration v3.0.0 completed successfully!' AS result;
