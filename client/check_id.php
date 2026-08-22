<?php
session_start();
header('Content-Type: application/json');
require_once '../db_connect.php';

$id_number = isset($_GET['id_number']) ? trim($_GET['id_number']) : '';
if ($id_number === '') {
    echo json_encode(['ok' => false, 'exists' => false, 'message' => 'No id_number provided']);
    exit;
}

try {
    $stmt = $pdo->prepare("SELECT 1 FROM users WHERE id_number = ? LIMIT 1");
    $stmt->execute([$id_number]);
    $exists = (bool)$stmt->fetchColumn();
    echo json_encode(['ok' => true, 'exists' => $exists]);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'exists' => false, 'message' => 'Database error']);
}

?>
