<?php
session_start();
header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../db_connect.php';
require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../includes/authorization.php';
require_once __DIR__ . '/../includes/csrf.php';

require_login();

$response = ['ok' => false, 'message' => ''];

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    $response['message'] = 'Invalid request.';
    echo json_encode($response);
    exit;
}
if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
    $response['message'] = 'Invalid security token. Please refresh and try again.';
    echo json_encode($response);
    exit;
}

$is_admin = isset($_SESSION['admin_id']);
$table = $is_admin ? 'admin_users' : 'users';
$user_id = $is_admin ? $_SESSION['admin_id'] : $_SESSION['user_id'];

$first = trim($_POST['first_name'] ?? '');
$last = trim($_POST['last_name'] ?? '');
$middle = strtoupper(trim($_POST['middle_initial'] ?? ''));
$sex = $_POST['sex'] ?? '';
$birthdate = trim($_POST['birthdate'] ?? '');
$email = trim($_POST['email'] ?? '');
$contact = trim($_POST['contact_number'] ?? '');
$address = trim($_POST['address'] ?? '');
$new_password = $_POST['new_password'] ?? '';
$confirm_password = $_POST['confirm_password'] ?? '';
$birthdate_valid = ($birthdate !== '' && DateTime::createFromFormat('Y-m-d', $birthdate) !== false && $birthdate <= date('Y-m-d'));

$errors = [];
if (($e = validate_name_field($first)) !== '') $errors[] = $e;
if (($e = validate_name_field($last)) !== '') $errors[] = $e;
if (($e = validate_middle_initial($middle)) !== '') $errors[] = $e;
if (!in_array($sex, ['Male', 'Female', 'Prefer not to say'], true)) $errors[] = 'Please select your gender.';
if (!$birthdate_valid) $errors[] = 'Please enter a valid birth date (not in the future).';
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = 'Please enter a valid email address.';
if (($e = validate_ph_contact($contact)) !== '') $errors[] = $e;
if (($e = validate_address_field($address, 'Address')) !== '') $errors[] = $e;
if ($new_password !== '') {
    if (strlen($new_password) < 8 || strlen($new_password) > 30) $errors[] = 'New password must be 8-30 characters.';
    elseif ($new_password !== $confirm_password) $errors[] = 'Passwords do not match.';
}

if ($errors) {
    $response['message'] = implode(' ', array_slice($errors, 0, 3));
    echo json_encode($response);
    exit;
}

try {
    $stmt = $pdo->prepare("SELECT id FROM $table WHERE email = ? AND id != ?");
    $stmt->execute([$email, $user_id]);
    if ($stmt->fetch()) {
        $response['message'] = 'This email is already in use by another account.';
        echo json_encode($response);
        exit;
    }

    $pdo->beginTransaction();
    $middle_sql = $middle !== '' ? $middle : null;
    $full_name = trim(preg_replace('/\s+/', ' ', trim($first . ' ' . $middle_sql . ' ' . $last)));

    if ($is_admin) {
        $sql = "UPDATE admin_users SET first_name = ?, middle_initial = ?, last_name = ?, sex = ?, birthdate = ?, contact_number = ?, email = ?, address = ?, full_name = ?, updated_at = CURRENT_TIMESTAMP";
        $params = [$first, $middle_sql, $last, $sex, $birthdate, $contact, $email, $address, $full_name];
    } else {
        $sql = "UPDATE users SET first_name = ?, middle_initial = ?, last_name = ?, sex = ?, birthdate = ?, contact_number = ?, email = ?, address_street = ?, updated_at = CURRENT_TIMESTAMP";
        $params = [$first, $middle_sql, $last, $sex, $birthdate, $contact, $email, $address];
    }
    if ($new_password !== '') {
        $sql .= ", password = ?";
        $params[] = password_hash($new_password, PASSWORD_DEFAULT);
    }
    $sql .= " WHERE id = ?";
    $params[] = $user_id;
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);

    if ($is_admin) {
        $_SESSION['admin_full_name'] = $full_name;
        $_SESSION['admin_email'] = $email;
    } else {
        $_SESSION['full_name'] = $full_name;
        $_SESSION['email'] = $email;
    }

    $pdo->commit();
    log_audit($pdo, 'profile_update', $table, $user_id, $full_name, 'Completed account details' . ($new_password !== '' ? ' and changed password' : ''));
    $response['ok'] = true;
    $response['message'] = 'Profile updated successfully.';
} catch (Throwable $e) {
    if ($pdo->inTransaction()) $pdo->rollBack();
    error_log('[complete_profile] ' . $e->getMessage());
    $response['message'] = 'Database error. Please try again.';
}

echo json_encode($response);