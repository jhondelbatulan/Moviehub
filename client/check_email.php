<?php
session_start();
header('Content-Type: application/json');
require_once '../db_connect.php';

$email = isset($_GET['email']) ? trim($_GET['email']) : '';
if ($email === '') {
    echo json_encode(['ok' => false, 'available' => false, 'message' => 'No email provided']);
    exit;
}

try {
    $stmt = $pdo->prepare("SELECT 1 FROM users WHERE email = ? LIMIT 1");
    $stmt->execute([$email]);
    $exists = (bool)$stmt->fetchColumn();
    echo json_encode(['ok' => true, 'available' => !$exists]);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'available' => false, 'message' => 'Database error']);
}
?>
