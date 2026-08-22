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
if ($username === '') {
    echo json_encode(['ok' => false, 'message' => 'Username is required.']);
    exit;
}

try {
    $stmt = $pdo->prepare('SELECT id, id_number FROM users WHERE username = ? AND is_deleted = 0');
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    if (!$user) {
        echo json_encode(['ok' => false, 'message' => 'Username not found.']);
        exit;
    }

    $stmt2 = $pdo->prepare('SELECT sq.id, sq.question_text FROM secret_questions sq INNER JOIN security_answers sa ON sa.question_id = sq.id WHERE sa.user_table = ? AND sa.user_id = ? ORDER BY sa.id');
    $stmt2->execute(['users', $user['id']]);
    $questions = $stmt2->fetchAll(PDO::FETCH_ASSOC);

    if (empty($questions)) {
        echo json_encode(['ok' => false, 'message' => 'No security questions found for this account.']);
        exit;
    }

    $formatted = [];
    foreach ($questions as $q) {
        $formatted[] = ['id' => $q['id'], 'question' => $q['question_text']];
    }

    echo json_encode([
        'ok' => true,
        'user_id' => $user['id'],
        'id_number' => $user['id_number'] ?? '',
        'security_questions' => $formatted
    ]);
} catch (PDOException $e) {
    error_log('Get security question error: ' . $e->getMessage());
    echo json_encode(['ok' => false, 'message' => 'Database error. Please try again later.']);
}
