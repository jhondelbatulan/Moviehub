<?php
session_start();
header('Content-Type: application/json');
require_once '../db_connect.php';

try {
    $stmt = $pdo->query("SELECT MAX(id) as maxid FROM users");
    $row = $stmt->fetch();
    $next = ($row && $row['maxid']) ? intval($row['maxid']) + 1 : 1;
    // Format as 8 digits and insert dash after 4 digits: xxxx-xxxx
    $numeric = str_pad((string)$next, 8, '0', STR_PAD_LEFT);
    $id_number = substr($numeric, 0, 4) . '-' . substr($numeric, 4, 4);
    echo json_encode(['ok' => true, 'id_number' => $id_number]);
} catch (Throwable $e) {
    http_response_code(500);
    error_log('[get_next_id.php] Error: ' . $e->getMessage());
    echo json_encode(['ok' => false, 'message' => 'Database error']);
}

?>
