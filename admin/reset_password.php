<?php
session_start();
header('Content-Type: application/json');
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/csrf.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'message' => 'Method not allowed']);
    exit;
}

if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
    echo json_encode(['ok' => false, 'message' => 'Invalid security token. Please refresh and try again.']);
    exit;
}

if (empty($_SESSION['reset_verified_user_id'])) {
    echo json_encode(['ok' => false, 'message' => 'Session expired. Please verify OTP again.']);
    exit;
}

$new_password = $_POST['new_password'] ?? '';
$new_password_confirm = $_POST['new_password_confirm'] ?? '';

if (strlen($new_password) < 8 || strlen($new_password) > 30) {
    echo json_encode(['ok' => false, 'message' => 'Password must be between 8 and 30 characters.']);
    exit;
}

if ($new_password !== $new_password_confirm) {
    echo json_encode(['ok' => false, 'message' => 'Passwords do not match.']);
    exit;
}

$user_id = (int)$_SESSION['reset_verified_user_id'];
$user_table = $_SESSION['reset_verified_user_table'] ?? 'admin_users';
unset($_SESSION['reset_verified_user_id'], $_SESSION['reset_verified_user_table']);

try {
    $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
    if ($user_table === 'users') {
        $stmt = $pdo->prepare("UPDATE users SET password = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?");
        $stmt->execute([$hashed_password, $user_id]);
    } else {
        $stmt = $pdo->prepare("SELECT full_name, username, account_status FROM admin_users WHERE id = ?");
        $stmt->execute([$user_id]);
        $who = $stmt->fetch(PDO::FETCH_ASSOC);
        $stmt = $pdo->prepare("UPDATE admin_users SET password = ?, must_change_password = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?");
        $stmt->execute([$hashed_password, $user_id]);
        if ($who) {
            log_audit($pdo, 'password_change', 'admin_users', $user_id, $who['full_name'] ?: $who['username'], 'Password reset via forgot-password flow; account status left as "' . $who['account_status'] . '"');
        }
    }

    echo json_encode(['ok' => true, 'message' => 'Password reset successfully! Redirecting to login...']);
} catch (PDOException $e) {
    error_log('Admin password reset error: ' . $e->getMessage());
    echo json_encode(['ok' => false, 'message' => 'Database error. Please try again later.']);
}
