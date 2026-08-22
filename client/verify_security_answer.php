<?php
session_start();
header('Content-Type: application/json');
require_once '../db_connect.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'message' => 'Method not allowed']);
    exit;
}

$username = trim($_POST['username'] ?? '');
$security_answer = trim($_POST['security_answer'] ?? '');
$question_id = intval($_POST['question_id'] ?? 0);

if ($username === '' || $security_answer === '' || $question_id === 0) {
    echo json_encode(['ok' => false, 'message' => 'All fields are required.']);
    exit;
}

try {
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

    if (!$record) {
        echo json_encode(['ok' => false, 'message' => 'Security question not found for this user.']);
        exit;
    }

    if (!password_verify(strtolower($security_answer), $record['answer_hash'])) {
        echo json_encode(['ok' => false, 'message' => 'Incorrect security answer. Please try again.']);
        exit;
    }

    $_SESSION['reset_verified_user_id'] = $user['id'];

    echo json_encode(['ok' => true, 'message' => 'Security answer verified.', 'question_id' => $question_id]);
} catch (PDOException $e) {
    error_log('Verify security answer error: ' . $e->getMessage());
    echo json_encode(['ok' => false, 'message' => 'Database error. Please try again later.']);
}
