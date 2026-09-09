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

function log_login($pdo, $user_table, $user_id, $username, $full_name, $role, $action, $status, $employee_id = null) {
    try {
        $stmt = $pdo->prepare("INSERT INTO login_logs (user_table, user_id, employee_id, full_name, username, role, action, status, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        $stmt->execute([$user_table, $user_id, $employee_id, $full_name, $username, $role, $action, $status, get_client_ip(), $_SERVER['HTTP_USER_AGENT'] ?? null]);
    } catch (PDOException $e) {
        error_log("Login log error: " . $e->getMessage());
    }
}

function generate_employee_id($pdo, $prefix = 'EMP') {
    $offset = strlen($prefix) + 2;
    $stmt = $pdo->prepare("SELECT MAX(CAST(SUBSTRING(employee_id, $offset) AS UNSIGNED)) as max_num FROM (SELECT employee_id FROM users WHERE employee_id LIKE ? UNION ALL SELECT employee_id FROM admin_users WHERE employee_id LIKE ?) combined");
    $stmt->execute([$prefix . '-%', $prefix . '-%']);
    $row = $stmt->fetch();
    $next = ($row && $row['max_num']) ? $row['max_num'] + 1 : 1;
    return $prefix . '-' . str_pad($next, 4, '0', STR_PAD_LEFT);
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
    $new_status = ($table === 'users') ? 'approved' : 'active';
    $stmt = $pdo->prepare("UPDATE $table SET account_status = ? WHERE id = ?");
    $stmt->execute([$new_status, $user_id]);
    record_status_change($pdo, $user_table, $user_id, 'blocked', $new_status);
}

function auto_inactivate_accounts($pdo) {
    try {
        $days = defined('AUTO_INACTIVE_DAYS') ? (int)AUTO_INACTIVE_DAYS : 30;
        $cutoff = date('Y-m-d H:i:s', time() - ($days * 86400));

        $admin_updated = 0;
        $stmt = $pdo->prepare("SELECT id FROM admin_users WHERE account_status = 'active' AND (COALESCE(last_login, created_at) < ?)");
        $stmt->execute([$cutoff]);
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $upd = $pdo->prepare("UPDATE admin_users SET account_status = 'inactive' WHERE id = ? AND account_status = 'active'");
            $upd->execute([$row['id']]);
            if ($upd->rowCount() > 0) {
                record_status_change($pdo, 'admin_users', $row['id'], 'active', 'inactive', 'Automatically set to inactive (' . $days . ' days without login)');
                $admin_updated++;
            }
        }

        $user_updated = 0;
        $stmt = $pdo->prepare("SELECT id FROM users WHERE account_status = 'approved' AND (COALESCE(last_login, created_at) < ?)");
        $stmt->execute([$cutoff]);
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $upd = $pdo->prepare("UPDATE users SET account_status = 'inactive' WHERE id = ? AND account_status = 'approved'");
            $upd->execute([$row['id']]);
            if ($upd->rowCount() > 0) {
                record_status_change($pdo, 'users', $row['id'], 'approved', 'inactive', 'Automatically set to inactive (' . $days . ' days without login)');
                $user_updated++;
            }
        }

        return ['admins' => $admin_updated, 'users' => $user_updated];
    } catch (PDOException $e) {
        error_log("Auto-inactive error: " . $e->getMessage());
        return ['admins' => 0, 'users' => 0];
    }
}


function get_all_users_paginated($pdo, $filters = [], $per_page = 10, $page = 1) {
    $where = ["u.is_deleted = 0"]; $params = [];
    if (!empty($filters['search'])) {
        $where[] = "(u.first_name LIKE ? OR u.last_name LIKE ? OR u.username LIKE ? OR u.email LIKE ? OR u.id_number LIKE ? OR u.employee_id LIKE ?)";
        $s = "%{$filters['search']}%"; $params = array_merge($params, [$s, $s, $s, $s, $s, $s]);
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
        $where[] = "(a.full_name LIKE ? OR a.username LIKE ? OR a.email LIKE ? OR a.employee_id LIKE ?)";
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

function get_employee_id_by_record($pdo, $user_table, $user_id) {
    $table = ($user_table === 'admin_users') ? 'admin_users' : 'users';
    $stmt = $pdo->prepare("SELECT employee_id FROM $table WHERE id = ?");
    $stmt->execute([$user_id]); $row = $stmt->fetch();
    return $row ? ($row['employee_id'] ?? '') : '';
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
