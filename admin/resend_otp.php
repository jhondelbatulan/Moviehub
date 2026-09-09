<?php
session_start();
header('Content-Type: application/json');
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/otp.php';
require_once '../includes/csrf.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'message' => 'Method not allowed']);
    exit;
}

if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
    echo json_encode(['ok' => false, 'message' => 'Invalid security token.']);
    exit;
}

if (empty($_SESSION['otp_user_id']) || empty($_SESSION['otp_purpose'])) {
    echo json_encode(['ok' => false, 'message' => 'No pending OTP session. Please start over.']);
    exit;
}

$user_id = $_SESSION['otp_user_id'];
$user_table = $_SESSION['otp_user_table'] ?? 'admin_users';
$purpose = $_SESSION['otp_purpose'];

if (!can_resend_otp($pdo, $user_table, $user_id, $purpose)) {
    echo json_encode(['ok' => false, 'message' => 'Too many requests. Please wait before trying again.']);
    exit;
}

$stmt = $pdo->prepare("SELECT full_name, email FROM admin_users WHERE id = ?");
$stmt->execute([$user_id]);
$admin = $stmt->fetch();

if (!$admin) {
    echo json_encode(['ok' => false, 'message' => 'Account not found.']);
    exit;
}

$otp = create_otp($pdo, $user_table, $user_id, $purpose);
send_otp_email($admin['email'], $otp, $admin['full_name']);

echo json_encode(['ok' => true, 'message' => 'OTP resent successfully.']);
