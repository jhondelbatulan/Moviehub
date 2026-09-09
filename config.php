<?php
// ============================================================
// MovieHub - Movie Rental System - Configuration
// Version: 2.0.0
// ============================================================

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Site Configuration
define('SITE_NAME', 'MovieHub');
define('SITE_URL', 'http://localhost/Moviehub');
define('SITE_VERSION', '2.0.0');

// Database Configuration
define('DB_HOST', 'localhost');
define('DB_NAME', 'moviehub_db');
define('DB_USER', 'root');
define('DB_PASS', '');

// Security Configuration
define('SESSION_TIMEOUT', 3600);
define('PASSWORD_MIN_LENGTH', 8);
define('PASSWORD_MAX_LENGTH', 30);
define('MAX_LOGIN_ATTEMPTS', 5);

// OTP Configuration
define('OTP_LENGTH', 6);
define('OTP_EXPIRY_MINUTES', 5);
define('OTP_MAX_ATTEMPTS', 5);
define('OTP_RESEND_COOLDOWN', 60);

// File Upload Configuration
define('UPLOAD_PATH', 'uploads/');
define('MAX_FILE_SIZE', 5 * 1024 * 1024);
define('ALLOWED_IMAGE_TYPES', ['jpg', 'jpeg', 'png', 'gif']);

// Pagination Configuration
define('RECORDS_PER_PAGE', 10);

// Email Configuration (configure your SMTP here)
define('SMTP_HOST', 'smtp.gmail.com');
define('SMTP_PORT', 587);
define('SMTP_USERNAME', 'denniscasuco0@gmail.com');
define('SMTP_PASSWORD', 'gdlooidlojlxtxjc');
define('SMTP_FROM_NAME', 'MovieHub System');
define('SMTP_FROM_EMAIL', 'denniscasuco0@gmail.com');
define('EMAIL_ENABLED', true);

// Application Settings
define('CURRENCY_SYMBOL', '₱');
define('CURRENCY_CODE', 'PHP');
define('DATE_FORMAT', 'Y-m-d');
define('DATETIME_FORMAT', 'Y-m-d H:i:s');

// Error Reporting - PRODUCTION: set to false
define('DEBUG_MODE', false);

if (DEBUG_MODE) {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
} else {
    error_reporting(0);
    ini_set('display_errors', 0);
    ini_set('log_errors', 1);
    ini_set('error_log', __DIR__ . '/logs/php_error.log');
}

// Timezone
date_default_timezone_set('Asia/Manila');

// Roles
define('ROLE_SUPER_ADMIN', 'super_admin');
define('ROLE_ADMIN', 'admin');
define('ROLE_USER', 'user');

// Account Statuses
define('STATUS_PENDING', 'pending');
define('STATUS_APPROVED', 'approved');
define('STATUS_REJECTED', 'rejected');
define('STATUS_BLOCKED', 'blocked');
define('STATUS_ACTIVE', 'active');
define('STATUS_INACTIVE', 'inactive');

// Lockout Configuration
define('LOCKOUT_THRESHOLD', 3);
define('LOCKOUT_INITIAL_SECONDS', 15);

// Secret Questions
define('SECRET_QUESTIONS_REQUIRED', 3);
define('SECRET_QUESTIONS_MIN_CORRECT', 2);

// OTP
define('OTP_MAX_RESEND_PER_HOUR', 5);

// Auto-Inactive: mark accounts inactive after this many days without login
define('AUTO_INACTIVE_DAYS', 30);