<?php
session_start();
header('Content-Type: application/json');
// For security policy, do not implement admin password resets via security questions.
echo json_encode(['ok' => false, 'message' => 'Admin password reset is not enabled. Please contact the system administrator.']);
?>

