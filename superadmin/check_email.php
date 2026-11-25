<?php
session_start();
header('Content-Type: application/json');
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/authorization.php';

require_login();
require_role('super_admin');
require_permission('admins.create');

$email = trim($_GET['email'] ?? '');
if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(['ok' => false, 'available' => false, 'message' => 'Enter a valid email address.']);
    exit;
}

echo json_encode(['ok' => true, 'available' => !email_taken($pdo, $email)]);
