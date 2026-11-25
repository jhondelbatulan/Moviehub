<?php
require_once __DIR__ . '/functions.php';
require_once __DIR__ . '/csrf.php';

function require_login() {
    if (session_status() === PHP_SESSION_NONE) session_start();
    $is_pending_setup = !empty($_SESSION['pending_admin_setup']) || !empty($_SESSION['pending_user_setup']);
    if (!is_logged_in() && !$is_pending_setup) {
        flash_message('error', 'Please log in to continue.');
        $base = get_auth_redirect_base();
        redirect($base . 'login.php');
    }
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > SESSION_TIMEOUT) {
        $pdo = $GLOBALS['pdo'] ?? null;
        if ($pdo && isset($_SESSION['admin_id'])) {
            log_login($pdo, 'admin_users', $_SESSION['admin_id'], $_SESSION['admin_username'] ?? '', $_SESSION['admin_full_name'] ?? '', $_SESSION['admin_role'] ?? '', 'logout', 'success', $_SESSION['admin_id_number'] ?? null);
        } elseif ($pdo && isset($_SESSION['user_id'])) {
            log_login($pdo, 'users', $_SESSION['user_id'], $_SESSION['username'] ?? '', $_SESSION['full_name'] ?? '', $_SESSION['user_role'] ?? 'user', 'logout', 'success', $_SESSION['id_number'] ?? null);
        }
        session_unset(); session_destroy(); session_start();
        flash_message('error', 'Session expired. Please log in again.');
        $base = get_auth_redirect_base();
        redirect($base . 'login.php');
    }
    $_SESSION['last_activity'] = time();

    $pdo = $GLOBALS['pdo'] ?? null;
    if ($pdo && isset($_SESSION['admin_id'])) {
        try {
            $stmt = $pdo->prepare("SELECT account_status FROM admin_users WHERE id = ?");
            $stmt->execute([$_SESSION['admin_id']]);
            $live = $stmt->fetchColumn();
            if ($live === 'inactive' || $live === 'blocked') {
                log_login($pdo, 'admin_users', $_SESSION['admin_id'], $_SESSION['admin_username'] ?? '', $_SESSION['admin_full_name'] ?? '', $_SESSION['admin_role'] ?? '', 'logout', 'success', $_SESSION['admin_id_number'] ?? null);
                session_unset(); session_destroy(); session_start();
                flash_message('error', $live === 'blocked' ? 'Your account is blocked.' : 'Your account is inactive. It must be activated by another admin.');
                $base = get_auth_redirect_base();
                redirect($base . 'login.php');
            }
        } catch (PDOException $e) {
            error_log("[require_login] status check error: " . $e->getMessage());
        }
    }
    if ($pdo && isset($_SESSION['user_id'])) {
        try {
            $stmt = $pdo->prepare("SELECT account_status FROM users WHERE id = ?");
            $stmt->execute([$_SESSION['user_id']]);
            $live = $stmt->fetchColumn();
            if ($live === 'blocked' || $live === 'pending' || $live === 'rejected') {
                log_login($pdo, 'users', $_SESSION['user_id'], $_SESSION['username'] ?? '', $_SESSION['full_name'] ?? '', $_SESSION['user_role'] ?? 'user', 'logout', 'success', $_SESSION['id_number'] ?? null);
                session_unset(); session_destroy(); session_start();
                flash_message('error', $live === 'blocked' ? 'Your account is blocked.' : 'Your account is no longer active. Please contact support.');
                redirect('login.php');
            }
        } catch (PDOException $e) {
            error_log("[require_login] user status check error: " . $e->getMessage());
        }
    }

    $script = $_SERVER['SCRIPT_NAME'] ?? '';
    $is_change_pw = strpos($script, 'change_password.php') !== false;
    if (!$is_change_pw && !empty($_SESSION['must_change_password']) && (isset($_SESSION['admin_id']) || isset($_SESSION['user_id']))) {
        $base = get_auth_redirect_base();
        redirect($base . 'change_password.php');
    }
}

function get_auth_redirect_base() {
    $script = $_SERVER['SCRIPT_NAME'] ?? '';
    if (strpos($script, '/superadmin/') !== false) return '../superadmin/';
    if (strpos($script, '/admin/') !== false) return '../admin/';
    return '';
}

function require_role($roles) {
    if (session_status() === PHP_SESSION_NONE) session_start();
    require_login();
    if (!is_array($roles)) $roles = [$roles];
    $current_role = get_current_role();
    if (!in_array($current_role, $roles)) {
        flash_message('error', 'You do not have permission to access this page.');
        redirect_to_dashboard($current_role);
    }
}

function redirect_to_dashboard($role) {
    if ($role === 'user') redirect('../client/dashboard.php');
    if ($role === 'admin') redirect('../admin/dashboard.php');
    if ($role === 'super_admin') redirect('../superadmin/dashboard.php');
    redirect('../client/login.php');
}

function require_permission($permission_key) {
    global $pdo;
    if (session_status() === PHP_SESSION_NONE) session_start();
    require_login();

    if (isset($_SESSION['admin_id'])) {
        $user_table = 'admin_users'; $user_id = $_SESSION['admin_id'];
    } elseif (isset($_SESSION['user_id'])) {
        $user_table = 'users'; $user_id = $_SESSION['user_id'];
    } else {
        flash_message('error', 'Access denied.'); redirect('login.php');
    }

    if (!check_permission($pdo, $user_table, $user_id, $permission_key)) {
        $role = get_current_role();
        $role_label = ucfirst(str_replace('_', ' ', $role));
        $perm_label = ucfirst(str_replace('.', ' > ', $permission_key));
        $base = get_auth_redirect_base();
        ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Denied - MovieHub</title>
    <link rel="stylesheet" href="<?php echo $base; ?>assets/css/style.css?v=2.3.0">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body style="display:flex;align-items:center;justify-content:center;min-height:100vh;background:var(--background);">
    <div style="text-align:center;max-width:500px;padding:2rem;">
        <div style="width:80px;height:80px;border-radius:50%;background:rgba(239,68,68,0.1);display:flex;align-items:center;justify-content:center;margin:0 auto 1.5rem;">
            <i class="fas fa-lock" style="font-size:2rem;color:var(--danger);"></i>
        </div>
        <h1 style="font-size:1.5rem;margin-bottom:0.5rem;">Access Denied</h1>
        <p style="color:var(--text-light);margin-bottom:0.5rem;">Your <strong><?php echo $role_label; ?></strong> role does not have the <strong><?php echo $perm_label; ?></strong> permission.</p>
        <p style="color:var(--text-light);font-size:0.8125rem;margin-bottom:1.5rem;">Contact the Super Administrator if you believe this is a mistake.</p>
        <div style="display:flex;gap:0.75rem;justify-content:center;">
            <a href="javascript:history.back()" class="btn btn-outline"><i class="fas fa-arrow-left"></i> Go Back</a>
            <a href="<?php echo $base; ?>login.php" class="btn btn-primary"><i class="fas fa-sign-in-alt"></i> Login as Different User</a>
        </div>
    </div>
</body>
</html>
        <?php exit();
    }
}

function require_status_active() {
    if (session_status() === PHP_SESSION_NONE) session_start();
    require_login();
    $status = $_SESSION['account_status'] ?? null;
    if ($status && !in_array($status, [STATUS_ACTIVE, STATUS_APPROVED, STATUS_ONLINE], true)) {
        session_unset(); session_destroy(); session_start();
        flash_message('error', 'Your account has been ' . $status . '. Please contact support.');
        redirect('login.php');
    }
}

function check_user_password($pdo, $user_table, $user_id, $password) {
    $table = ($user_table === 'admin_users') ? 'admin_users' : 'users';
    $stmt = $pdo->prepare("SELECT password FROM $table WHERE id = ?");
    $stmt->execute([$user_id]); $row = $stmt->fetch();
    return $row && password_verify($password, $row['password']);
}

function is_super_admin_session() {
    return isset($_SESSION['admin_role']) && $_SESSION['admin_role'] === 'super_admin';
}

function is_admin_session() {
    return isset($_SESSION['admin_role']) && in_array($_SESSION['admin_role'], ['admin', 'super_admin']);
}

function get_user_table_and_id() {
    if (isset($_SESSION['admin_id'])) return ['admin_users', $_SESSION['admin_id']];
    if (isset($_SESSION['user_id'])) return ['users', $_SESSION['user_id']];
    return [null, null];
}
