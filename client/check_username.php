<?php
session_start();
header('Content-Type: application/json');
require_once '../db_connect.php';

$username = isset($_GET['username']) ? trim($_GET['username']) : '';
if ($username === '') {
    echo json_encode(['ok' => false, 'available' => false, 'message' => 'No username provided']);
    exit;
}

try {
    $stmt = $pdo->prepare("SELECT 1 FROM users WHERE username = ? LIMIT 1");
    $stmt->execute([$username]);
    $exists = (bool)$stmt->fetchColumn();
    echo json_encode(['ok' => true, 'available' => !$exists]);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'available' => false, 'message' => 'Database error']);
}
?>


