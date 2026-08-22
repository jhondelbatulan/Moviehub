<?php
// ============================================================
// CSRF Token Management
// ============================================================

function generate_csrf_token() {
    if (session_status() === PHP_SESSION_NONE) session_start();
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf_token($token) {
    if (session_status() === PHP_SESSION_NONE) session_start();
    return isset($_SESSION['csrf_token']) && isset($token) && hash_equals($_SESSION['csrf_token'], $token);
}

function csrf_field() {
    return '<input type="hidden" name="csrf_token" value="' . generate_csrf_token() . '">';
}

function csrf_token_input() {
    echo csrf_field();
}

function require_csrf() {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $token = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        if (!verify_csrf_token($token)) {
            http_response_code(403);
            if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest') {
                header('Content-Type: application/json');
                echo json_encode(['ok' => false, 'message' => 'Invalid security token. Please refresh and try again.']);
            } else {
                $_SESSION['flash_error'] = 'Invalid security token. Please refresh and try again.';
                redirect($_SERVER['HTTP_REFERER'] ?? 'index.php');
            }
            exit();
        }
    }
}
