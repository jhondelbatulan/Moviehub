<?php
session_start();
header('Content-Type: application/json');
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';

$username = isset($_GET['username']) ? trim($_GET['username']) : '';
if ($username === '') {
    echo json_encode(['ok' => false, 'available' => false, 'message' => 'No username provided']);
    exit;
}

try {
    $exists = username_taken($pdo, $username);
    echo json_encode(['ok' => true, 'available' => !$exists]);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'available' => false, 'message' => 'Database error']);
}
?>


