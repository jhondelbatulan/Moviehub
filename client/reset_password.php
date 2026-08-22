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

$new_password = $_POST['new_password'] ?? '';
$new_password_confirm = $_POST['new_password_confirm'] ?? '';
$via_otp = isset($_POST['via_otp']);

if (strlen($new_password) < 8 || strlen($new_password) > 30) {
    echo json_encode(['ok' => false, 'message' => 'Password must be between 8 and 30 characters.']);
    exit;
}

if ($new_password !== $new_password_confirm) {
    echo json_encode(['ok' => false, 'message' => 'Passwords do not match.']);
    exit;
}

try {
    if ($via_otp) {
        if (empty($_SESSION['reset_verified_user_id'])) {
            echo json_encode(['ok' => false, 'message' => 'Session expired. Please verify OTP again.']);
            exit;
        }
        $user_id = $_SESSION['reset_verified_user_id'];
        unset($_SESSION['reset_verified_user_id'], $_SESSION['security_verified']);
    } else {
        $username = trim($_POST['username'] ?? '');
        $question_id = intval($_POST['question_id'] ?? 0);
        $security_answer = trim($_POST['security_answer'] ?? '');

        if ($username === '' || $question_id === 0 || $security_answer === '') {
            echo json_encode(['ok' => false, 'message' => 'All verification fields are required.']);
            exit;
        }

        $stmt = $pdo->prepare('SELECT id FROM users WHERE username = ? AND is_deleted = 0');
        $stmt->execute([$username]);
        $user = $stmt->fetch();

        if (!$user) {
            echo json_encode(['ok' => false, 'message' => 'User not found.']);
            exit;
        }

        $stmt2 = $pdo->prepare('SELECT id, answer_hash FROM security_answers WHERE user_table = ? AND user_id = ? AND question_id = ?');
        $stmt2->execute(['users', $user['id'], $question_id]);
        $record = $stmt2->fetch();

        if (!$record || !password_verify(strtolower($security_answer), $record['answer_hash'])) {
            echo json_encode(['ok' => false, 'message' => 'Security verification failed.']);
            exit;
        }

        $user_id = $user['id'];
    }

    $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
    $update_stmt = $pdo->prepare('UPDATE users SET password = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?');
    $update_stmt->execute([$hashed_password, $user_id]);

    if (isset($_SESSION['login_attempts'])) {
        $_SESSION['login_attempts'] = 0;
    }

    echo json_encode(['ok' => true, 'message' => 'Password reset successfully! Redirecting to login...']);
} catch (PDOException $e) {
    error_log('Password reset error: ' . $e->getMessage());
    echo json_encode(['ok' => false, 'message' => 'Database error. Please try again later.']);
}
