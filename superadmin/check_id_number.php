<?php
session_start();
header('Content-Type: application/json');
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/authorization.php';

require_login();
require_role('super_admin');

$id_number = trim($_GET['id_number'] ?? '');

if (!preg_match('/^\d{4}-\d{4}$/', $id_number)) {
    echo json_encode(['ok' => true, 'exists' => false, 'taken_by' => '']);
    exit;
}

$exists = false;
$taken_by = '';
try {
    $stmt = $pdo->prepare("SELECT 'admin_users' AS tbl FROM admin_users WHERE id_number = ? AND is_deleted = 0 UNION SELECT 'pending_admin' AS tbl FROM pending_admin_accounts WHERE id_number = ? UNION SELECT 'pending_user' AS tbl FROM pending_user_accounts WHERE id_number = ? UNION SELECT 'users' AS tbl FROM users WHERE id_number = ? AND is_deleted = 0 LIMIT 1");
    $stmt->execute([$id_number, $id_number, $id_number, $id_number]);
    $row = $stmt->fetch();
    if ($row) {
        $exists = true;
        $taken_by = $row['tbl'];
    }
} catch (PDOException $e) {
    error_log('[check_id_number] ' . $e->getMessage());
}

echo json_encode(['ok' => true, 'exists' => $exists, 'taken_by' => $taken_by]);