<?php
// ============================================================
// Helper Functions
// ============================================================

if (!defined('SITE_NAME')) require_once __DIR__ . '/../config.php';

function sanitize_input($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    return $data;
}

function format_currency($amount) {
    return CURRENCY_SYMBOL . number_format((float)$amount, 2);
}

function format_date($date, $format = DATE_FORMAT) {
    return date($format, strtotime($date));
}

function format_datetime($date) {
    return date(DATETIME_FORMAT, strtotime($date));
}

function redirect($url) {
    header("Location: $url");
    exit();
}

function mask_email($email) {
    $parts = explode('@', $email);
    if (count($parts) !== 2) return $email;
    $name = $parts[0];
    if (strlen($name) <= 2) {
        $masked = substr($name, 0, 1) . str_repeat('*', max(0, strlen($name) - 1));
    } else {
        $masked = substr($name, 0, 2) . str_repeat('*', max(0, strlen($name) - 2));
    }
    $domain = $parts[1];
    $dparts = explode('.', $domain);
    if (count($dparts) >= 2) {
        $tld = array_pop($dparts);
        $domain_masked = substr(implode('.', $dparts), 0, 2) . '***.' . $tld;
    } else {
        $domain_masked = $domain;
    }
return $masked . '@' . $domain_masked;
}

function mask_id_number($id_number) {
    $id_number = (string)$id_number;
    if (!preg_match('/^(\d{4})-?(\d{4})$/', $id_number, $m)) return '****-****';
    $a = $m[1]; $b = $m[2];
    return substr($a, 0, 2) . '**-**' . substr($b, 2, 2);
}

function get_next_id_number($pdo) {
    try {
        $stmt = $pdo->query("
            SELECT CAST(REPLACE(id_number,'-','') AS UNSIGNED) AS n FROM users WHERE is_deleted = 0 AND id_number IS NOT NULL AND id_number <> ''
            UNION SELECT CAST(REPLACE(id_number,'-','') AS UNSIGNED) FROM admin_users WHERE is_deleted = 0 AND id_number IS NOT NULL AND id_number <> ''
            UNION SELECT CAST(REPLACE(id_number,'-','') AS UNSIGNED) FROM pending_admin_accounts WHERE id_number IS NOT NULL AND id_number <> ''
            UNION SELECT CAST(REPLACE(id_number,'-','') AS UNSIGNED) FROM pending_user_accounts WHERE id_number IS NOT NULL AND id_number <> ''
        ");
        $max = 0;
        foreach ($stmt->fetchAll(PDO::FETCH_COLUMN) as $n) {
            if ((int)$n > $max) $max = (int)$n;
        }
        $next = sprintf('%08d', $max + 1);
        return substr($next, 0, 4) . '-' . substr($next, 4, 4);
    } catch (PDOException $e) {
        error_log('[get_next_id_number] ' . $e->getMessage());
        return '0000-0001';
    }
}

function generate_password($length = 12) {
    $upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
    $lower = 'abcdefghijkmnopqrstuvwxyz';
    $digits = '23456789';
    $symbols = '!@#$%^&*()-_+';
    $all = $upper . $lower . $digits . $symbols;
    $pw = $upper[random_int(0, strlen($upper) - 1)]
        . $lower[random_int(0, strlen($lower) - 1)]
        . $digits[random_int(0, strlen($digits) - 1)]
        . $symbols[random_int(0, strlen($symbols) - 1)];
    for ($i = 4; $i < $length; $i++) {
        $pw .= $all[random_int(0, strlen($all) - 1)];
    }
    return str_shuffle($pw);
}

function validate_strong_password($password) {
    $password = (string)$password;
    if (strlen($password) < 8 || strlen($password) > 30) return 'Password must be 8-30 characters.';
    if (preg_match('/\s/', $password)) return 'Password cannot contain spaces.';
    $categories = 0;
    if (preg_match('/[A-Za-z]/', $password)) $categories++;
    if (preg_match('/[0-9]/', $password)) $categories++;
    if (preg_match('/[^A-Za-z0-9]/', $password)) $categories++;
    if ($categories < 2) return 'Password is weak. Combine letters with numbers or symbols.';
    return '';
}

function validate_name_field($name) {
    $name = trim((string)$name);
    if ($name === '') return '';
    if (strlen($name) < 2 || strlen($name) > 30) return 'Name must be 2-30 characters.';
    if (!preg_match('/^[A-Z][a-z]+(?: [A-Z][a-z]+)*$/', $name)) return 'Must start with a capital letter, single spaces, with the rest in lowercase (e.g. Juan Dela Cruz).';
    if (preg_match('/^[A-Z]+$/', $name)) return 'Cannot be all capital letters.';
    if (preg_match('/([A-Z][a-z]*)[A-Z]/', $name)) return 'Cannot have camel-case letters in the middle of a name.';
    if (preg_match('/[0-9]/', $name) || preg_match('/[^A-Za-z ]/', $name)) return 'Cannot contain numbers or special characters.';
    if (preg_match('/(.)\1{2,}/', $name)) return 'Cannot have three or more consecutive identical letters.';
    return '';
}

function validate_middle_initial($mi) {
    $mi = strtoupper(trim((string)$mi));
    if ($mi === '') return '';
    if (!preg_match('/^[A-Z]$/', $mi)) return 'Middle initial must be a single capital letter only.';
    return '';
}

function validate_extension_name($ext) {
    $ext = trim((string)$ext);
    if ($ext === '') return '';
    if (!preg_match('/^(Jr\.?|Sr\.?|II|III|IV|V|VI|VII|VIII|IX|X)$/i', $ext)) return 'Extension must be Jr., Sr., or a Roman numeral (II, III, IV, etc.).';
    return '';
}

function validate_birthdate($birthdate) {
    $birthdate = trim((string)$birthdate);
    if ($birthdate === '') return 'Birth date is required.';
    $d = DateTime::createFromFormat('Y-m-d', $birthdate);
    $errors = DateTime::getLastErrors();
    if (!$d || ($errors && ($errors['warning_count'] > 0 || $errors['error_count'] > 0))) return 'Enter a valid birth date.';
    if ($birthdate > date('Y-m-d')) return 'Birth date cannot be in the future.';
    if (compute_age($birthdate) > 120) return 'Birth date appears to be invalid (age over 120).';
    return '';
}

function validate_address_field($value, $label = 'Address') {
    $value = trim((string)$value);
    if ($value === '') return '';
    if (strlen($value) < 2 || strlen($value) > 100) return $label . ' must be 2-100 characters.';
    if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9 .,\'#-]*$/', $value)) return $label . ' contains invalid characters.';
    if (!preg_match('/[A-Za-z]/', $value)) return $label . ' must contain at least one letter.';
    return '';
}

function validate_ph_contact($contact) {
    $contact = trim((string)$contact);
    if ($contact === '') return '';
    $n = preg_replace('/[^0-9]/', '', $contact);
    if (strpos($n, '63') === 0) $n = substr($n, 2);
    if (strpos($n, '0') === 0) $n = substr($n, 1);
    if (preg_match('/^9\d{9}$/', $n)) return '';
    return 'Enter a valid Philippine mobile number (e.g. 0917-123-4567 or +63 917 123 4567).';
}

function compute_age($birthdate) {
    if (empty($birthdate)) return '';
    try {
        $d = new DateTime($birthdate);
    } catch (Exception $e) {
        return '';
    }
    return (new DateTime('now'))->diff($d)->y;
}

function is_profile_complete($row, $is_admin = false) {
    if (!$row) return false;
    foreach (['first_name', 'last_name', 'sex', 'birthdate', 'contact_number', 'email'] as $col) {
        if (!isset($row[$col]) || trim((string)$row[$col]) === '') return false;
    }
    return true;
}

function is_logged_in() {
    return isset($_SESSION['user_id']) || isset($_SESSION['admin_id']);
}

function is_admin() {
    return isset($_SESSION['admin_role']) && in_array($_SESSION['admin_role'], ['admin', 'super_admin']);
}

function is_super_admin() {
    return isset($_SESSION['admin_role']) && $_SESSION['admin_role'] === 'super_admin';
}

function get_current_user_id() {
    return $_SESSION['user_id'] ?? $_SESSION['admin_id'] ?? null;
}

function get_current_role() {
    if (isset($_SESSION['user_id'])) return 'user';
    if (isset($_SESSION['admin_role'])) return $_SESSION['admin_role'];
    return null;
}

function get_base_path() {
    $path = $_SERVER['SCRIPT_NAME'];
    if (strpos($path, '/admin/') !== false || strpos($path, '/superadmin/') !== false) {
        return '../';
    }
    return '';
}

function get_current_page() {
    $page = basename($_SERVER['SCRIPT_NAME'], '.php');
    return $page;
}

function flash_message($key, $message = null) {
    if ($message !== null) {
        $_SESSION['flash_' . $key] = $message;
    } else {
        $msg = $_SESSION['flash_' . $key] ?? null;
        unset($_SESSION['flash_' . $key]);
        return $msg;
    }
}

function get_client_ip() {
    $keys = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
    foreach ($keys as $key) {
        if (!empty($_SERVER[$key])) {
            $ip = trim(explode(',', $_SERVER[$key])[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
    }
    return '127.0.0.1';
}

function paginate($total_records, $current_page, $per_page = RECORDS_PER_PAGE) {
    $total_pages = max(1, ceil($total_records / $per_page));
    $current_page = max(1, min($current_page, $total_pages));
    $offset = ($current_page - 1) * $per_page;

    return [
        'total' => $total_records,
        'per_page' => $per_page,
        'current_page' => $current_page,
        'total_pages' => $total_pages,
        'offset' => $offset,
        'has_prev' => $current_page > 1,
        'has_next' => $current_page < $total_pages,
        'prev_page' => max(1, $current_page - 1),
        'next_page' => min($total_pages, $current_page + 1),
        'from' => $total_records > 0 ? $offset + 1 : 0,
        'to' => min($offset + $per_page, $total_records)
    ];
}

function render_pagination($pagination, $base_url = '') {
    if ($pagination['total_pages'] <= 1) return '';

    $sep = strpos($base_url, '?') !== false ? '&' : '?';

    $html = '<div class="pagination">';
    $html .= '<div class="pagination-info">Showing ' . $pagination['from'] . '–' . $pagination['to'] . ' of ' . $pagination['total'] . ' records</div>';
    $html .= '<div class="pagination-controls">';

    if ($pagination['has_prev']) {
        $html .= '<a href="' . $base_url . $sep . 'page=' . $pagination['prev_page'] . '" class="pagination-btn"><i class="fas fa-chevron-left"></i></a>';
    }

    $start = max(1, $pagination['current_page'] - 2);
    $end = min($pagination['total_pages'], $pagination['current_page'] + 2);

    if ($start > 1) {
        $html .= '<a href="' . $base_url . $sep . 'page=1" class="pagination-btn">1</a>';
        if ($start > 2) $html .= '<span class="pagination-ellipsis">...</span>';
    }

    for ($i = $start; $i <= $end; $i++) {
        $active = $i === $pagination['current_page'] ? ' active' : '';
        $html .= '<a href="' . $base_url . $sep . 'page=' . $i . '" class="pagination-btn' . $active . '">' . $i . '</a>';
    }

    if ($end < $pagination['total_pages']) {
        if ($end < $pagination['total_pages'] - 1) $html .= '<span class="pagination-ellipsis">...</span>';
        $html .= '<a href="' . $base_url . $sep . 'page=' . $pagination['total_pages'] . '" class="pagination-btn">' . $pagination['total_pages'] . '</a>';
    }

    if ($pagination['has_next']) {
        $html .= '<a href="' . $base_url . $sep . 'page=' . $pagination['next_page'] . '" class="pagination-btn"><i class="fas fa-chevron-right"></i></a>';
    }

    $html .= '</div></div>';
    return $html;
}

function log_audit($pdo, $action, $target_table = null, $target_id = null, $target_name = null, $details = null) {
    try {
        $actor_table = null;
        $actor_id = null;
        $actor_name = null;
        $actor_role = null;

        if (isset($_SESSION['admin_id'])) {
            $actor_table = 'admin_users';
            $actor_id = $_SESSION['admin_id'];
            $actor_name = $_SESSION['admin_full_name'] ?? $_SESSION['admin_username'] ?? 'Unknown';
            $actor_role = $_SESSION['admin_role'] ?? 'unknown';
        } elseif (isset($_SESSION['user_id'])) {
            $actor_table = 'users';
            $actor_id = $_SESSION['user_id'];
            $actor_name = $_SESSION['full_name'] ?? $_SESSION['username'] ?? 'Unknown';
            $actor_role = 'user';
        }

        $stmt = $pdo->prepare("INSERT INTO audit_logs (actor_table, actor_id, actor_name, actor_role, action, target_table, target_id, target_name, details, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        $stmt->execute([$actor_table, $actor_id, $actor_name, $actor_role, $action, $target_table, $target_id, $target_name, $details, get_client_ip()]);
    } catch (PDOException $e) {
        error_log("Audit log error: " . $e->getMessage());
    }
}

function log_login($pdo, $user_table, $user_id, $username, $full_name, $role, $action, $status, $id_number = null) {
    try {
        $stmt = $pdo->prepare("INSERT INTO login_logs (user_table, user_id, id_number, full_name, username, role, action, status, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        $stmt->execute([$user_table, $user_id, $id_number, $full_name, $username, $role, $action, $status, get_client_ip(), $_SERVER['HTTP_USER_AGENT'] ?? null]);
    } catch (PDOException $e) {
        error_log("Login log error: " . $e->getMessage());
    }
}

function get_user_by_id($pdo, $user_id) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ? AND is_deleted = 0");
    $stmt->execute([$user_id]);
    return $stmt->fetch();
}

function get_admin_by_id($pdo, $admin_id) {
    $stmt = $pdo->prepare("SELECT * FROM admin_users WHERE id = ? AND is_deleted = 0");
    $stmt->execute([$admin_id]);
    return $stmt->fetch();
}

function check_permission($pdo, $user_table, $user_id, $permission_key) {
    // super_admin has all permissions
    if ($user_table === 'admin_users') {
        $stmt = $pdo->prepare("SELECT role FROM admin_users WHERE id = ?");
        $stmt->execute([$user_id]);
        $admin = $stmt->fetch();
        if ($admin && $admin['role'] === 'super_admin') return true;
    }

    // Check user_permissions override first
    $stmt = $pdo->prepare("
        SELECT up.granted FROM user_permissions up
        JOIN permissions p ON up.permission_id = p.id
        WHERE up.user_table = ? AND up.user_id = ? AND p.permission_key = ?
    ");
    $stmt->execute([$user_table, $user_id, $permission_key]);
    $override = $stmt->fetch();
    if ($override) return (bool)$override['granted'];

    // Check role_permissions
    $role = null;
    if ($user_table === 'admin_users') {
        $stmt = $pdo->prepare("SELECT role FROM admin_users WHERE id = ?");
        $stmt->execute([$user_id]);
        $admin = $stmt->fetch();
        $role = $admin ? $admin['role'] : null;
    } else {
        $stmt = $pdo->prepare("SELECT role FROM users WHERE id = ?");
        $stmt->execute([$user_id]);
        $user = $stmt->fetch();
        $role = $user ? $user['role'] : 'user';
    }

    if (!$role) return false;

    $stmt = $pdo->prepare("
        SELECT rp.granted FROM role_permissions rp
        JOIN permissions p ON rp.permission_id = p.id
        WHERE rp.role = ? AND p.permission_key = ?
    ");
    $stmt->execute([$role, $permission_key]);
    $perm = $stmt->fetch();
    return $perm ? (bool)$perm['granted'] : false;
}

function generate_otp($length = 6) {
    $otp = '';
    for ($i = 0; $i < $length; $i++) { $otp .= random_int(0, 9); }
    return $otp;
}

function create_otp($pdo, $user_table, $user_id, $purpose = 'password_reset') {
    $otp = generate_otp(OTP_LENGTH);
    $otp_hash = password_hash($otp, PASSWORD_DEFAULT);
    $expires = date('Y-m-d H:i:s', time() + (OTP_EXPIRY_MINUTES * 60));
    $stmt = $pdo->prepare("UPDATE otp_codes SET used = 1 WHERE user_table = ? AND user_id = ? AND purpose = ? AND used = 0");
    $stmt->execute([$user_table, $user_id, $purpose]);
    $stmt = $pdo->prepare("INSERT INTO otp_codes (user_table, user_id, otp_hash, purpose, expires_at) VALUES (?, ?, ?, ?, ?)");
    $stmt->execute([$user_table, $user_id, $otp_hash, $purpose, $expires]);
    return $otp;
}

function verify_otp($pdo, $user_table, $user_id, $otp_input, $purpose = 'password_reset') {
    $stmt = $pdo->prepare("SELECT id, otp_hash, expires_at, attempts FROM otp_codes WHERE user_table = ? AND user_id = ? AND purpose = ? AND used = 0 ORDER BY id DESC LIMIT 1");
    $stmt->execute([$user_table, $user_id, $purpose]);
    $record = $stmt->fetch();
    if (!$record) return ['success' => false, 'message' => 'No OTP found. Please request a new one.'];
    if (strtotime($record['expires_at']) < time()) return ['success' => false, 'message' => 'OTP has expired. Please request a new one.'];
    if ($record['attempts'] >= OTP_MAX_ATTEMPTS) {
        $stmt = $pdo->prepare("UPDATE otp_codes SET used = 1 WHERE id = ?");
        $stmt->execute([$record['id']]);
        return ['success' => false, 'message' => 'Too many failed attempts. Please request a new OTP.'];
    }
    $stmt = $pdo->prepare("UPDATE otp_codes SET attempts = attempts + 1 WHERE id = ?");
    $stmt->execute([$record['id']]);
    if (!password_verify($otp_input, $record['otp_hash'])) return ['success' => false, 'message' => 'Invalid OTP. Please try again.'];
    $stmt = $pdo->prepare("UPDATE otp_codes SET used = 1 WHERE id = ?");
    $stmt->execute([$record['id']]);
    return ['success' => true, 'message' => 'OTP verified successfully.'];
}

function can_resend_otp($pdo, $user_table, $user_id, $purpose = 'password_reset') {
    $one_hour_ago = date('Y-m-d H:i:s', time() - 3600);
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM otp_codes WHERE user_table = ? AND user_id = ? AND purpose = ? AND created_at > ?");
    $stmt->execute([$user_table, $user_id, $purpose, $one_hour_ago]);
    return $stmt->fetchColumn() < OTP_MAX_RESEND_PER_HOUR;
}

function record_status_change($pdo, $user_table, $user_id, $old_status, $new_status, $reason = null) {
    try {
        $actor_table = null; $actor_id = null;
        if (isset($_SESSION['admin_id'])) { $actor_table = 'admin_users'; $actor_id = $_SESSION['admin_id']; }
        elseif (isset($_SESSION['user_id'])) { $actor_table = 'users'; $actor_id = $_SESSION['user_id']; }
        $stmt = $pdo->prepare("INSERT INTO account_status_history (user_table, user_id, old_status, new_status, reason, changed_by_table, changed_by_id) VALUES (?, ?, ?, ?, ?, ?, ?)");
        $stmt->execute([$user_table, $user_id, $old_status, $new_status, $reason, $actor_table, $actor_id]);
    } catch (PDOException $e) { error_log("Status history error: " . $e->getMessage()); }
}

function block_account($pdo, $user_table, $user_id, $reason = null) {
    $table = ($user_table === 'admin_users') ? 'admin_users' : 'users';
    $old = ($table === 'users') ? 'approved' : 'active';
    $stmt = $pdo->prepare("UPDATE $table SET account_status = 'blocked' WHERE id = ?");
    $stmt->execute([$user_id]);
    record_status_change($pdo, $user_table, $user_id, $old, 'blocked', $reason);
}

function unblock_account($pdo, $user_table, $user_id) {
    $table = ($user_table === 'admin_users') ? 'admin_users' : 'users';
    $new_status = ($user_table === 'admin_users') ? 'inactive' : 'offline';
    $stmt = $pdo->prepare("UPDATE $table SET account_status = ? WHERE id = ?");
    $stmt->execute([$new_status, $user_id]);
    record_status_change($pdo, $user_table, $user_id, 'blocked', $new_status);
}

/**
 * Checks whether a username is already taken across every account table
 * (active users, admins, and pending accounts created by a super admin).
 */
function username_taken($pdo, $username) {
    $username = trim((string)$username);
    if ($username === '') return false;
    foreach (['users', 'admin_users', 'pending_user_accounts', 'pending_admin_accounts'] as $table) {
        try {
            $stmt = $pdo->prepare("SELECT 1 FROM $table WHERE username = ? LIMIT 1");
            $stmt->execute([$username]);
            if ($stmt->fetchColumn()) return true;
        } catch (PDOException $e) {
            error_log('[username_taken] ' . $table . ': ' . $e->getMessage());
        }
    }
    return false;
}

function email_taken($pdo, $email) {
    $email = trim((string)$email);
    if ($email === '') return false;
    foreach (['users', 'admin_users', 'pending_user_accounts', 'pending_admin_accounts'] as $table) {
        try {
            $where = in_array($table, ['users', 'admin_users'], true) ? 'email = ? AND is_deleted = 0' : 'email = ?';
            $stmt = $pdo->prepare("SELECT 1 FROM $table WHERE $where LIMIT 1");
            $stmt->execute([$email]);
            if ($stmt->fetchColumn()) return true;
        } catch (PDOException $e) {
            error_log('[email_taken] ' . $table . ': ' . $e->getMessage());
        }
    }
    return false;
}

function security_question_ids_are_valid($pdo, $question_ids, $required_count = 3) {
    $ids = array_map('intval', (array)$question_ids);
    if (count($ids) !== $required_count || in_array(0, $ids, true) || count(array_unique($ids)) !== $required_count) return false;
    $placeholders = implode(',', array_fill(0, count($ids), '?'));
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM secret_questions WHERE is_active = 1 AND id IN (1, 2, 3) AND id IN ($placeholders)");
    $stmt->execute($ids);
    return (int)$stmt->fetchColumn() === $required_count;
}

function count_super_admin_accounts($pdo) {
    $stmt = $pdo->query("SELECT
        (SELECT COUNT(*) FROM admin_users WHERE role = 'super_admin') +
        (SELECT COUNT(*) FROM pending_admin_accounts WHERE role = 'super_admin') +
        (SELECT COUNT(*) FROM users WHERE role = 'super_admin')");
    return (int)$stmt->fetchColumn();
}

function activate_admin_account($pdo, $target_id, $actor_role = null, $actor_id = null, $actor_name = null) {
    try {
        $actor_role = (string)$actor_role;
        if ($actor_role !== 'super_admin') {
            return ['success' => false, 'message' => 'Only a super admin can activate admin accounts.'];
        }

        $stmt = $pdo->prepare("SELECT id, username, full_name, role, account_status FROM admin_users WHERE id = ?");
        $stmt->execute([$target_id]);
        $target = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$target) {
            return ['success' => false, 'message' => 'Admin account not found.'];
        }
        if ($target['account_status'] === 'active') {
            return ['success' => false, 'message' => 'This admin account is already active.'];
        }
        if ($target['account_status'] !== 'inactive') {
            return ['success' => false, 'message' => 'Only inactive admin accounts can be activated.'];
        }
        if (!in_array((string)$target['role'], ['admin', 'super_admin'], true)) {
            return ['success' => false, 'message' => 'Only admin and super admin accounts can be activated here.'];
        }

        $role_label = ((string)$target['role'] === 'super_admin') ? 'super admin' : 'admin';

        $pdo->beginTransaction();

        $stmt = $pdo->prepare("SELECT id, full_name FROM admin_users WHERE id != ? AND account_status = 'active' AND role = ?");
        $stmt->execute([$target_id, $target['role']]);
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $old) {
            $upd = $pdo->prepare("UPDATE admin_users SET account_status = 'inactive', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND account_status = 'active'");
            $upd->execute([$old['id']]);
            if ($upd->rowCount() > 0) {
                record_status_change($pdo, 'admin_users', $old['id'], 'active', 'inactive', 'Replaced as the active ' . $role_label . ' when "' . $target['full_name'] . '" was activated');
            }
        }

        $from_status = $target['account_status'];
        $upd = $pdo->prepare("UPDATE admin_users SET account_status = 'active', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND account_status = 'inactive'");
        $upd->execute([$target_id]);
        record_status_change($pdo, 'admin_users', $target_id, $from_status, 'active', $actor_name ? ('Activated by ' . $actor_name) : 'Activated');

        log_audit($pdo, 'activate_account', 'admin_users', $target_id, $target['full_name'], $role_label . ' account activated by ' . ($actor_name ?: 'an admin'));

        $pdo->commit();
        return ['success' => true, 'target' => $target];
    } catch (PDOException $e) {
        if ($pdo->inTransaction()) { $pdo->rollBack(); }
        error_log('[activate_admin_account] ' . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to activate account.'];
    }
}

function deactivate_same_role_admins($pdo, $exclude_id, $role, $replaced_by = '') {
    $role = (string)$role;
    if (!in_array($role, ['super_admin', 'admin'], true)) {
        return 0;
    }
    $role_label = ($role === 'super_admin') ? 'super admin' : 'admin';
    $deactivated = 0;
    $reason = $replaced_by !== '' ? ('Replaced as the active ' . $role_label . ' when "' . $replaced_by . '" took over the ' . $role_label . ' seat') : ('No longer holds the active ' . $role_label . ' seat');
    $stmt = $pdo->prepare("SELECT id, full_name, username FROM admin_users WHERE id != ? AND account_status = 'active' AND role = ?");
    $stmt->execute([$exclude_id, $role]);
    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $old) {
        $upd = $pdo->prepare("UPDATE admin_users SET account_status = 'inactive', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND account_status = 'active'");
        $upd->execute([$old['id']]);
        if ($upd->rowCount() > 0) {
            $deactivated++;
            record_status_change($pdo, 'admin_users', $old['id'], 'active', 'inactive', $reason);
        }
    }
    return $deactivated;
}

function hard_delete_account($pdo, $user_table, $user_id, $keep_audit = true) {
    $table = ($user_table === 'admin_users') ? 'admin_users' : 'users';

    if ($table === 'users') {
        $stmt = $pdo->prepare("SELECT CONCAT(first_name, ' ', last_name) AS full_name, username, email FROM users WHERE id = ?");
    } else {
        $stmt = $pdo->prepare("SELECT full_name, username, email FROM admin_users WHERE id = ?");
    }
    $stmt->execute([$user_id]);
    $info = $stmt->fetch();
    $full_name = $info ? ($info['full_name'] ?? 'Unknown account') : 'Unknown account';

    $cascade = [
        ["security_answers", "user_table = ? AND user_id = ?", [$user_table, $user_id]],
        ["otp_codes", "user_table = ? AND user_id = ?", [$user_table, $user_id]],
        ["login_logs", "user_table = ? AND user_id = ?", [$user_table, $user_id]],
        ["account_status_history", "user_table = ? AND user_id = ?", [$user_table, $user_id]],
        ["user_permissions", "user_table = ? AND user_id = ?", [$user_table, $user_id]],
    ];
    if ($table === 'users') {
        $cascade[] = ["registration_approvals", "user_id = ?", [$user_id]];
        $cascade[] = ["rentals", "user_id = ?", [$user_id]];
    }
    if (!$keep_audit) {
        $cascade[] = ["deletion_requests", "target_table = ? AND target_id = ?", [$user_table, $user_id]];
        $cascade[] = ["account_deletion_documents", "target_table = ? AND target_id = ?", [$user_table, $user_id]];
        $cascade[] = ["password_change_documents", "target_table = ? AND target_id = ?", [$user_table, $user_id]];
        $cascade[] = ["block_requests", "target_table = ? AND target_id = ?", [$user_table, $user_id]];
        $cascade[] = ["block_request_documents", "target_table = ? AND target_id = ?", [$user_table, $user_id]];
    }

    foreach ($cascade as [$tbl, $where, $params]) {
        $pdo->prepare("DELETE FROM $tbl WHERE $where")->execute($params);
    }

    $stmt = $pdo->prepare("DELETE FROM $table WHERE id = ?");
    $stmt->execute([$user_id]);

    return ['id' => $user_id, 'full_name' => $full_name, 'username' => $info['username'] ?? '', 'email' => $info['email'] ?? ''];
}

function auto_inactivate_accounts($pdo) {
    try {
        $days = defined('AUTO_INACTIVE_DAYS') ? (int)AUTO_INACTIVE_DAYS : 30;
        $cutoff = date('Y-m-d H:i:s', time() - ($days * 86400));

        // Admin accounts are intentionally NOT auto-inactivated: only one active
        // admin is allowed at a time, so auto-inactivating it would lock the admin
        // out with no active admin left to re-activate it.

        $user_updated = 0;
        $stmt = $pdo->prepare("SELECT id FROM users WHERE account_status = 'approved' AND (last_login IS NULL OR last_login < ?)");
        $stmt->execute([$cutoff]);
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $upd = $pdo->prepare("UPDATE users SET account_status = 'offline' WHERE id = ? AND account_status = 'approved'");
            $upd->execute([$row['id']]);
            if ($upd->rowCount() > 0) {
                $user_updated++;
            }
        }

        return ['admins' => 0, 'users' => $user_updated];
    } catch (PDOException $e) {
        error_log("Auto-inactive error: " . $e->getMessage());
        return ['admins' => 0, 'users' => 0];
    }
}


function get_all_users_paginated($pdo, $filters = [], $per_page = 10, $page = 1) {
    $where = ["u.is_deleted = 0"]; $params = [];
if (!empty($filters['search'])) {
        $where[] = "(u.first_name LIKE ? OR u.last_name LIKE ? OR u.username LIKE ? OR u.email LIKE ? OR u.id_number LIKE ?)";
        $s = "%{$filters['search']}%"; $params = array_merge($params, [$s, $s, $s, $s, $s]);
    }
    if (!empty($filters['role'])) { $where[] = "u.role = ?"; $params[] = $filters['role']; }
    if (!empty($filters['status'])) { $where[] = "u.account_status = ?"; $params[] = $filters['status']; }
    $where_sql = 'WHERE ' . implode(' AND ', $where);
    $count_stmt = $pdo->prepare("SELECT COUNT(*) FROM users u $where_sql");
    $count_stmt->execute($params); $total = $count_stmt->fetchColumn();
    $pagination = paginate($total, $page, $per_page);
    $stmt = $pdo->prepare("SELECT u.* FROM users u $where_sql ORDER BY u.id DESC LIMIT {$pagination['per_page']} OFFSET {$pagination['offset']}");
    $stmt->execute($params); $users = $stmt->fetchAll();
    return ['users' => $users, 'pagination' => $pagination, 'total' => $total];
}

function get_all_admins_paginated($pdo, $filters = [], $per_page = 10, $page = 1) {
    $where = ["a.is_deleted = 0"]; $params = [];
if (!empty($filters['search'])) {
        $where[] = "(a.full_name LIKE ? OR a.username LIKE ? OR a.email LIKE ? OR a.id_number LIKE ?)";
        $s = "%{$filters['search']}%"; $params = array_merge($params, [$s, $s, $s, $s]);
    }
    if (!empty($filters['role'])) { $where[] = "a.role = ?"; $params[] = $filters['role']; }
    if (!empty($filters['status'])) { $where[] = "a.account_status = ?"; $params[] = $filters['status']; }
    $where_sql = 'WHERE ' . implode(' AND ', $where);
    $count_stmt = $pdo->prepare("SELECT COUNT(*) FROM admin_users a $where_sql");
    $count_stmt->execute($params); $total = $count_stmt->fetchColumn();
    $pagination = paginate($total, $page, $per_page);
    $stmt = $pdo->prepare("SELECT a.* FROM admin_users a $where_sql ORDER BY a.id DESC LIMIT {$pagination['per_page']} OFFSET {$pagination['offset']}");
    $stmt->execute($params); $admins = $stmt->fetchAll();
    return ['admins' => $admins, 'pagination' => $pagination, 'total' => $total];
}

function render_status_badge($status) {
    $class = 'status-badge status-' . $status;
    return '<span class="' . $class . '">' . ucfirst(htmlspecialchars($status)) . '</span>';
}

function render_role_badge($role) {
    $colors = ['super_admin' => 'badge-purple', 'admin' => 'badge-info', 'user' => 'badge-success'];
    $class = $colors[$role] ?? 'badge-secondary';
    $label = ucfirst(str_replace('_', ' ', $role));
    return '<span class="badge ' . $class . '">' . $label . '</span>';
}

function get_full_name($pdo, $user_table, $user_id) {
    $table = ($user_table === 'admin_users') ? 'admin_users' : 'users';
    if ($table === 'admin_users') { $stmt = $pdo->prepare("SELECT full_name FROM admin_users WHERE id = ?"); }
    else { $stmt = $pdo->prepare("SELECT CONCAT(first_name, ' ', last_name) as full_name FROM users WHERE id = ?"); }
    $stmt->execute([$user_id]); $row = $stmt->fetch();
    return $row ? $row['full_name'] : 'Unknown';
}

function movie_poster_url($path) {
    $path = trim((string)$path);
    if ($path === '') return '';
    if (preg_match('~^https?://~i', $path)) return $path;
    $path = str_replace('\\', '/', $path);
    while (strpos($path, '../') === 0) { $path = substr($path, 3); }
    $path = ltrim($path, '/');
    if (!defined('SITE_URL') || SITE_URL === '') return $path;
    return rtrim(SITE_URL, '/') . '/' . $path;
}
