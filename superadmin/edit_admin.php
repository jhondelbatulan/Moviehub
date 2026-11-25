<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/authorization.php';
require_once '../includes/csrf.php';

require_login();
$editing_admin_id = intval($_GET['id'] ?? 0);
if (get_current_role() === 'super_admin') {
    require_role('super_admin');
} else {
    require_role('admin');
}

$admin_id = $editing_admin_id;
$error = '';
$is_owner = (intval($_SESSION['admin_id'] ?? 0) === $admin_id);
$is_super = (($_SESSION['admin_role'] ?? '') === 'super_admin');
$base = $is_super ? '' : '../admin/';
$manage_link = $is_super ? 'account_management.php' : '../admin/account_management.php';

if ($is_super && !$is_owner) {
    $target_role_stmt = $pdo->prepare('SELECT role FROM admin_users WHERE id = ? AND is_deleted = 0');
    $target_role_stmt->execute([$admin_id]);
    if ($target_role_stmt->fetchColumn() === 'super_admin') {
        flash_message('error', 'You do not have permission to edit another super admin account.');
        redirect('account_management.php');
    }
}

if (!$is_super && !$is_owner) {
    // Admins may edit the info of other admin accounts, but never super admin accounts.
    $target_role = false;
    try {
        $stmt = $pdo->prepare("SELECT role FROM admin_users WHERE id = ? AND is_deleted = 0");
        $stmt->execute([$admin_id]);
        $target_role = $stmt->fetchColumn();
    } catch (PDOException $e) {
        error_log('[edit_admin] target lookup failed: ' . $e->getMessage());
    }
    if ($target_role === false || $target_role === null) {
        flash_message('error', 'Admin account not found.');
        redirect('../admin/account_management.php');
    }
    if ($target_role === 'super_admin') {
        flash_message('error', 'You do not have permission to edit super admin accounts.');
        redirect('../admin/account_management.php');
    }
    require_permission('admins.update');
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if ($admin_id <= 0) {
        $error = 'Invalid admin ID.';
    } elseif (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token.';
    } elseif (($_POST['editor_password'] ?? '') === '') {
        $error = 'Please enter your current password to verify this change.';
    } elseif (!check_user_password($pdo, 'admin_users', $_SESSION['admin_id'], $_POST['editor_password'] ?? '')) {
        $error = 'Inputted password is wrong.';
    } else {
        $full_name = trim($_POST['full_name'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $phone = trim($_POST['phone'] ?? '');
        $address = trim($_POST['address'] ?? '');
        $current_password = $_POST['current_password'] ?? '';
        $new_password = $_POST['new_password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';
        $role_stmt = $pdo->prepare('SELECT role FROM admin_users WHERE id = ? AND is_deleted = 0');
        $role_stmt->execute([$admin_id]);
        $role = (string)$role_stmt->fetchColumn();
        $account_status = $_POST['account_status'] ?? '';
        $sq_ids = [(int)($_POST['sq1_id'] ?? 0), (int)($_POST['sq2_id'] ?? 0), (int)($_POST['sq3_id'] ?? 0)];
        $sq_answers = [trim($_POST['sq1_answer'] ?? ''), trim($_POST['sq2_answer'] ?? ''), trim($_POST['sq3_answer'] ?? '')];
        $security_questions_changed = $is_owner && count(array_filter($sq_answers, function ($answer) { return $answer !== ''; })) > 0;

        $ok = true;
        if ($is_owner) {
            $ok = $ok && ($full_name !== '' && $email !== '');
            if ($security_questions_changed && in_array('', $sq_answers, true)) { $error = 'Fill in all three answers to update your security questions.'; $ok = false; }
            elseif ($security_questions_changed && !security_question_ids_are_valid($pdo, $sq_ids)) { $error = 'Choose three different active security questions.'; $ok = false; }
            if ($new_password !== '') {
                if ($current_password === '') { $error = 'Enter your current password to change it.'; $ok = false; }
            elseif (!check_user_password($pdo, 'admin_users', $admin_id, $current_password)) { $error = 'Inputted password is wrong.'; $ok = false; }
                elseif (strlen($new_password) < 8 || strlen($new_password) > 30) { $error = 'New password must be 8-30 characters.'; $ok = false; }
                elseif ($new_password !== $confirm_password) { $error = 'Passwords do not match.'; $ok = false; }
            }
            if ($ok && !filter_var($email, FILTER_VALIDATE_EMAIL)) { $error = 'Invalid email address.'; $ok = false; }
            if ($ok && ($e = validate_name_field($full_name)) !== '') { $error = $e; $ok = false; }
        } else {
            if (!in_array($role, ['admin', 'super_admin'], true)) { $error = 'Invalid role.'; $ok = false; }
            if ($ok && ($full_name === '' || $email === '')) { $error = 'Full name and email are required.'; $ok = false; }
            if ($ok && !filter_var($email, FILTER_VALIDATE_EMAIL)) { $error = 'Invalid email address.'; $ok = false; }
            if ($ok && ($e = validate_name_field($full_name)) !== '') { $error = $e; $ok = false; }
            if ($ok && $phone !== '' && ($e = validate_ph_contact($phone)) !== '') { $error = 'Contact number must be a valid Philippine mobile number (e.g. 0917-123-4567).'; $ok = false; }
        }

        $prev_status = null;
        $prev_role = null;
        if ($ok) {
            try {
                if ($is_owner) {
                    if ($phone !== '' && ($e = validate_ph_contact($phone)) !== '') {
                        $error = 'Contact number must be a valid Philippine mobile number (e.g. 0917-123-4567).';
                        $ok = false;
                    }
                    if ($ok) {
                        $stmt = $pdo->prepare("SELECT id FROM admin_users WHERE email = ? AND id != ?");
                        $stmt->execute([$email, $admin_id]);
                        if ($stmt->fetch()) {
                            $error = 'That email address is already used by another account.';
                            $ok = false;
                        }
                    }
                } else {
                    $stmt = $pdo->prepare("SELECT id FROM admin_users WHERE email = ? AND id != ?");
                    $stmt->execute([$email, $admin_id]);
                    if ($stmt->fetch()) {
                        $error = 'That email address is already used by another account.';
                        $ok = false;
                    }
                    $stmt = $pdo->prepare("SELECT role, account_status FROM admin_users WHERE id = ?");
                    $stmt->execute([$admin_id]);
                    $prev = $stmt->fetch(PDO::FETCH_ASSOC);
                    $prev_status = $prev['account_status'] ?? null;
                    $prev_role = $prev['role'] ?? null;
                    $account_status = $prev_status;
                    if ($prev_status !== 'active' && $account_status === 'active') {
                        if ($role !== (string)$_SESSION['admin_role'] || $prev_role !== (string)$_SESSION['admin_role']) {
                            $label = ($_SESSION['admin_role'] === 'super_admin') ? 'super admin accounts' : 'admin accounts';
                            $error = 'You can only activate ' . $label . '.';
                            $ok = false;
                        }
                    }
                }
            } catch (PDOException $e) {
                error_log('[edit_admin] ' . $e->getMessage());
                $error = 'Failed to validate account.';
                $ok = false;
            }
        }

        if ($ok) {
            try {
                if ($is_owner) {
                    $sql = "UPDATE admin_users SET full_name = ?, email = ?, phone = ?, address = ?";
                    $params = [
                        $full_name,
                        $email,
                        $phone !== '' ? $phone : null,
                        $address !== '' ? $address : null
                    ];
                    if ($new_password !== '') { $sql .= ", password = ?"; $params[] = password_hash($new_password, PASSWORD_DEFAULT); }
                    $sql .= " WHERE id = ?"; $params[] = $admin_id;
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute($params);
                } else {
                    if ($prev_status !== 'active' && $account_status === 'active') {
                        $res = activate_admin_account($pdo, $admin_id, $_SESSION['admin_role'] ?? '', $_SESSION['admin_id'] ?? null, $_SESSION['admin_full_name'] ?? '');
                        if (!$res['success']) {
                            $error = $res['message'];
                        } else {
                            $target_name = $res['target']['full_name'] ?: $res['target']['username'];
                            $role_label = ($res['target']['role'] === 'super_admin') ? 'super admin' : 'admin';
                            log_login($pdo, 'admin_users', $_SESSION['admin_id'], $_SESSION['admin_username'] ?? '', $_SESSION['admin_full_name'] ?? '', $_SESSION['admin_role'] ?? '', 'logout', 'success', $_SESSION['admin_id_number'] ?? null);
                            log_audit($pdo, 'logout', 'admin_users', $_SESSION['admin_id'], $_SESSION['admin_full_name'] ?? '', 'Logged out automatically after activating "' . $target_name . '"');
                            $msg = '"' . $target_name . '" has been activated and is now the only active ' . $role_label . ' account. Your account is marked inactive and you have been logged out. Only one active ' . $role_label . ' is allowed at a time.';
                            $login_url = ($_SESSION['admin_role'] === 'super_admin') ? '../admin/login.php' : 'login.php';
                            session_unset(); session_destroy(); session_start();
                            flash_message('success', $msg);
                            redirect($login_url);
                        }
                    } else {
                        if ($role === 'admin' && $account_status === 'active') {
                            deactivate_same_role_admins($pdo, $admin_id, 'admin', $admin['full_name'] ?? '');
                        }
                        $stmt = $pdo->prepare("UPDATE admin_users SET account_status = ?, full_name = ?, email = ?, phone = ?, address = ? WHERE id = ?");
                        $stmt->execute([$account_status, $full_name, $email, $phone !== '' ? $phone : null, $address !== '' ? $address : null, $admin_id]);
                    }
                }

                if ($error === '') {
                    $nstmt = $pdo->prepare("SELECT full_name FROM admin_users WHERE id = ?");
                    $nstmt->execute([$admin_id]);
                    $target_name = (string)($nstmt->fetchColumn() ?: $admin_id);
                    log_audit($pdo, 'profile_update', 'admin_users', $admin_id, $target_name, $is_owner ? 'Own profile updated' : 'Admin account updated by ' . ($is_super ? 'Super Admin' : 'Admin "' . ($_SESSION['admin_username'] ?? '') . '" (id ' . (int)($_SESSION['admin_id'] ?? 0) . ')') . ' (role=' . $role . ', status=' . $account_status . '; personal info edited)');

                    if ($is_owner) {
                        if ($security_questions_changed) {
                            $del = $pdo->prepare("DELETE FROM security_answers WHERE user_table = 'admin_users' AND user_id = ?");
                            $del->execute([$admin_id]);
                            $ins = $pdo->prepare("INSERT INTO security_answers (user_table, user_id, question_id, answer_hash) VALUES ('admin_users', ?, ?, ?)");
                            for ($i = 0; $i < 3; $i++) {
                                $answer_hash = password_hash(strtolower(trim($sq_answers[$i])), PASSWORD_DEFAULT);
                                $ins->execute([$admin_id, $sq_ids[$i], $answer_hash]);
                            }
                        }
                    }

                    redirect('edit_admin.php?id=' . $admin_id . '&updated=1');
                }
            } catch (PDOException $e) {
                error_log('[edit_admin] ' . $e->getMessage());
                $error = 'Failed to update admin account.';
            }
        }
    }
}

$admin = null;
if ($admin_id > 0) {
    try {
        $stmt = $pdo->prepare("SELECT * FROM admin_users WHERE id = ? AND is_deleted = 0");
        $stmt->execute([$admin_id]);
        $admin = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$admin) {
            $error = 'Admin not found.';
        }
    } catch (PDOException $e) {
        error_log('[edit_admin] ' . $e->getMessage());
        $error = 'Failed to load admin account.';
    }
} else {
    $error = 'No admin ID specified.';
}

$existing_security = [];
if ($is_owner && $admin) {
    try {
        $stmt = $pdo->prepare("SELECT question_id, answer_hash FROM security_answers WHERE user_table = 'admin_users' AND user_id = ?");
        $stmt->execute([$admin_id]);
        $existing_security = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        $existing_security = [];
    }
}

$secret_questions = [];
try {
    $secret_questions = $pdo->query("SELECT id, question_text FROM secret_questions WHERE is_active = 1 AND id IN (1, 2, 3) ORDER BY sort_order, id")->fetchAll(PDO::FETCH_ASSOC);
} catch (Exception $e) {
    $secret_questions = [];
}

$updated = isset($_GET['updated']);
generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit Admin - MovieHub</title>
    <link rel="stylesheet" href="../assets/css/style.css?v=2.3.0">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body>
    <div class="page-wrapper">
<aside class="sidebar" id="sidebar">
            <div class="sidebar-header"><a href="<?php echo $base; ?>dashboard.php" class="sidebar-logo"><i class="fas fa-film"></i><span>MovieHub</span></a></div>
            <nav class="sidebar-nav">
<?php require __DIR__ . '/../includes/sidebar_navigation.php'; ?>
</nav>
            <a href="edit_admin.php?id=<?php echo (int)$_SESSION['admin_id']; ?>" class="sidebar-user" style="display:flex;align-items:center;gap:0.75rem;padding:0.75rem 1rem;color:inherit;text-decoration:none;transition:background 0.15s;cursor:pointer;" title="Edit my profile">
                <div class="avatar avatar-sm" style="background:var(--primary);color:white;"><?php echo strtoupper(substr($_SESSION['admin_full_name'], 0, 1)); ?></div>
                <div class="sidebar-user-info">
                    <div class="sidebar-user-name"><?php echo htmlspecialchars($_SESSION['admin_full_name']); ?></div>
                    <div class="sidebar-user-role" style="color:var(--primary);font-weight:600;"><?php echo $is_super ? 'Super Admin' : ucfirst(str_replace('_', ' ', $_SESSION['admin_role'] ?? 'admin')); ?></div>
                </div>
            </a>
        </aside>

        <div class="main-content">
            <div class="top-header">
                <div class="flex items-center gap-3">
                    <button class="sidebar-toggle" onclick="document.getElementById('sidebar').classList.toggle('open');document.getElementById('sidebarOverlay').classList.toggle('active');"><i class="fas fa-bars"></i></button>
                    <div><h1 class="page-title">Edit Admin</h1><p class="page-subtitle"><?php echo $admin ? 'Update details for ' . htmlspecialchars($admin['full_name']) : 'Update administrator account details'; ?></p></div>
                </div>
            </div>

            <div class="content-body">
                <?php if ($updated): ?><div class="alert alert-success"><i class="fas fa-check-circle"></i> Admin account updated successfully.</div><?php endif; ?>
                <?php if ($error): ?><div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div><?php endif; ?>

                <?php if ($admin): ?>
<div style="margin-bottom:1rem;">
                    <a href="<?php echo $manage_link; ?>" class="btn btn-outline btn-sm"><i class="fas fa-arrow-left"></i> Back to Account Management</a>
                </div>

                <div class="card" style="max-width:700px;">
                    <div class="card-header"><h3 class="card-title"><i class="fas fa-user-shield"></i> Administrator Details</h3></div>
                    <div class="card-body">
                        <form method="POST" action="">
                            <?php csrf_token_input(); ?>
                            <div style="display:grid;grid-template-columns:1fr 1fr;gap:0 1rem;">
                                <div class="form-group"><label>ID Number</label><input type="text" class="form-control" value="<?php echo htmlspecialchars($admin['id_number'] ?? ''); ?>" readonly disabled></div>
                                <div class="form-group"><label>Username</label><input type="text" class="form-control" value="<?php echo htmlspecialchars($admin['username']); ?>" readonly disabled></div>
                            </div>

                            <?php if ($is_owner): ?>
                            <div class="form-group"><label>Full Name *</label><input type="text" name="full_name" class="form-control" required maxlength="100" value="<?php echo htmlspecialchars($admin['full_name']); ?>"></div>
                            <div class="form-group"><label>Email *</label><input type="email" name="email" class="form-control" required maxlength="100" value="<?php echo htmlspecialchars($admin['email']); ?>"></div>
                            <div class="form-group"><label>Phone</label><input type="tel" name="phone" class="form-control" maxlength="20" value="<?php echo htmlspecialchars($admin['phone'] ?? ''); ?>"></div>
                            <div class="form-group"><label>Address</label><input type="text" name="address" class="form-control" maxlength="255" value="<?php echo htmlspecialchars($admin['address'] ?? ''); ?>"></div>
                            <?php else: ?>
                            <div class="form-group"><label>Full Name *</label><input type="text" name="full_name" class="form-control" required maxlength="100" value="<?php echo htmlspecialchars($admin['full_name']); ?>"></div>
                            <div class="form-group"><label>Email *</label><input type="email" name="email" class="form-control" required maxlength="100" value="<?php echo htmlspecialchars($admin['email']); ?>"></div>
                            <div class="form-group"><label>Phone</label><input type="tel" name="phone" class="form-control" maxlength="20" value="<?php echo htmlspecialchars($admin['phone'] ?? ''); ?>"></div>
                            <div class="form-group"><label>Address</label><input type="text" name="address" class="form-control" maxlength="255" value="<?php echo htmlspecialchars($admin['address'] ?? ''); ?>"></div>
                            <div class="alert alert-info" style="font-size:0.8125rem;"><i class="fas fa-info-circle"></i> You can edit this admin's information. All changes are recorded in the audit logs.</div>
                            <?php endif; ?>

                            <?php if ($is_owner): ?>
                            <div style="display:grid;grid-template-columns:1fr 1fr;gap:0 1rem;">
                                <div class="form-group"><label>Role</label><input type="text" class="form-control" value="<?php echo ($admin['role'] ?? 'admin') === 'super_admin' ? 'Super Admin' : 'Admin'; ?>" readonly disabled></div>
                                <div class="form-group"><label>Account Status</label><input type="text" class="form-control" value="<?php echo ucfirst($admin['account_status'] ?? 'active'); ?>" readonly disabled></div>
                            </div>
                            <?php else: ?>
                            <div style="display:grid;grid-template-columns:1fr 1fr;gap:0 1rem;">
                                <div class="form-group"><label>Role</label><input type="text" class="form-control" value="<?php echo ($admin['role'] ?? 'admin') === 'super_admin' ? 'Super Admin' : 'Admin'; ?>" readonly disabled></div>
                                <div class="form-group"><label>Account Status</label><input type="text" class="form-control" value="<?php echo ucfirst($admin['account_status'] ?? 'active'); ?>" readonly disabled
                                <?php if ($admin['account_status'] === 'inactive'): ?> title="Activate this account from Account Management to enable the seat handover."<?php endif; ?>></div>
                            </div>
                            <?php endif; ?>

                            <?php if ($is_owner): ?>
                            <div class="card" style="background:var(--surface-2);border:1px dashed var(--border);margin-top:1rem;">
                                <div class="card-header"><h3 class="card-title"><i class="fas fa-key"></i> Change Password</h3></div>
                                <div class="card-body">
                                    <div class="form-row">
                                        <div class="form-group"><label>Current Password</label><input type="password" name="current_password" class="form-control" autocomplete="current-password" placeholder="Required to change password"></div>
                                        <div class="form-group"><label>New Password</label><input type="password" name="new_password" class="form-control" minlength="8" maxlength="30" autocomplete="new-password" placeholder="8-30 characters"></div>
                                        <div class="form-group"><label>Confirm New Password</label><input type="password" name="confirm_password" class="form-control" minlength="8" maxlength="30" autocomplete="new-password" placeholder="Repeat new password"></div>
                                    </div>
                                </div>
                            </div>
                            <div class="card" style="background:var(--surface-2);border:1px dashed var(--border);margin-top:1rem;">
                                <div class="card-body">
                                    <label style="font-weight:700;font-size:0.8125rem;color:var(--text);display:block;margin-bottom:0.25rem;"><i class="fas fa-shield-alt" style="color:var(--primary);"></i> Security Questions</label>
                                    <small style="display:block;color:var(--text-light);font-size:0.75rem;margin-bottom:0.75rem;">Set 3 security questions and answers. These are used to recover your password if your account is ever locked out.</small>
                                    <?php
                                    $existing_qids = array_column($existing_security, 'question_id');
                                    for ($i = 0; $i < 3; $i++): ?>
                                        <div class="form-group">
                                            <label>Security Question <?php echo $i + 1; ?></label>
                                            <select name="sq<?php echo $i + 1; ?>_id" class="form-control sq-select" data-idx="<?php echo $i; ?>">
                                                <option value="0">-- Select a question --</option>
                                                <?php foreach ($secret_questions as $q): ?>
                                                    <option value="<?php echo $q['id']; ?>" <?php echo (isset($existing_qids[$i]) && (int)$existing_qids[$i] === (int)$q['id']) ? 'selected' : ''; ?>><?php echo htmlspecialchars($q['question_text']); ?></option>
                                                <?php endforeach; ?>
                                            </select>
                                        </div>
                                        <div class="form-group">
                                            <label>Answer <?php echo $i + 1; ?> <?php echo isset($existing_qids[$i]) ? '(leave blank to keep current answer)' : ''; ?></label>
                                            <input type="text" name="sq<?php echo $i + 1; ?>_answer" class="form-control" placeholder="Your answer" autocomplete="off">
                                        </div>
                                    <?php endfor; ?>
                                    <small style="font-size:0.6875rem;color:var(--muted);">To save security questions, select 3 different questions. If all answers are left blank, existing answers are kept.</small>
                                </div>
                            </div>
                            <?php endif; ?>

                            <div class="card" style="background:var(--surface-2);border:1px dashed var(--border);margin-top:1rem;">
                                <div class="card-body" style="padding:0.75rem 1rem;">
                                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:0 1rem;">
                                        <div class="form-group"><label>Your Password (to verify change) *</label><input type="password" name="editor_password" class="form-control" required placeholder="Enter YOUR current password to confirm changes" autocomplete="off"></div>
                                    </div>
                                    <small style="font-size:0.6875rem;color:var(--muted);">You must enter your own password before changes are saved.</small>
                                </div>
                            </div>
                            <div style="display:flex;gap:0.75rem;margin-top:1rem;">
                                <button type="submit" class="btn btn-primary"><i class="fas fa-save"></i> Save Changes</button>
                                <a href="<?php echo $manage_link; ?>" class="btn btn-outline">Cancel</a>
                            </div>
                        </form>
                        <script>
                        (function () {
                            var selects = document.getElementsByClassName('sq-select');
                            function refresh() {
                                var selectedQuestions = {};
                                for (var i = 0; i < selects.length; i++) {
                                    if (selects[i].value !== '0') selectedQuestions[selects[i].value] = true;
                                }
                                for (var i = 0; i < selects.length; i++) {
                                    for (var j = 0; j < selects[i].options.length; j++) {
                                        var option = selects[i].options[j];
                                        option.disabled = option.value !== '0' && selectedQuestions[option.value] === true && option.value !== selects[i].value;
                                    }
                                }
                            }
                            for (var i = 0; i < selects.length; i++) {
                                selects[i].addEventListener('change', refresh);
                            }
                            refresh();

                            var phone = document.getElementsByName('phone')[0];
                            if (phone) {
                                var fn = document.getElementsByName('full_name')[0];
                                function nameOk(v) {
                                    v = v.trim();
                                    if (!v) return false;
                                    if (v.length < 2 || v.length > 30) return false;
                                    if (!/^[A-Z][a-z]+(?: [A-Z][a-z]+)*$/.test(v)) return false;
                                    if (/^[A-Z]+$/.test(v)) return false;
                                    if (/[0-9]/.test(v) || /[^A-Za-z ]/.test(v)) return false;
                                    if (/(.)\1{2,}/.test(v)) return false;
                                    return true;
                                }
                                function phOk(v) { v = v.trim(); if (!v) return true; var n = v.replace(/[^0-9]/g, ''); if (n.indexOf('63') === 0) n = n.substring(2); if (n.indexOf('0') === 0) n = n.substring(1); return /^9\d{9}$/.test(n); }
                                var fns = document.createElement('small'), pns = document.createElement('small');
                                [fns, pns].forEach(function (s) { s.style.display = 'block'; s.style.fontSize = '0.6875rem'; s.style.minHeight = '0.9em'; });
                                fn.parentNode.appendChild(fns); phone.parentNode.appendChild(pns);
                                function set(el, ok, msg) { el.textContent = msg; el.style.color = ok ? 'var(--success)' : 'var(--danger)'; }
                                fn.addEventListener('input', function () { var v = this.value.trim(); nameOk(v) ? set(fns, true, 'Valid') : set(fns, false, v ? 'First letter capital, single spaces, no numbers/special chars.' : ''); });
                                phone.addEventListener('input', function () { var v = this.value.trim(); if (!v) { this.setCustomValidity(''); pns.textContent = ''; return; } var ok = phOk(v); this.setCustomValidity(ok ? '' : 'Use PH format'); set(pns, ok, ok ? 'Valid' : 'Use PH format, e.g. 0917-123-4567'); });
                            }
                        })();
                        </script>
                    </div>
                </div>
                <?php else: ?>
                <div class="card" style="max-width:700px;"><div class="card-body text-center" style="padding:2rem;"><p class="text-muted">No admin selected.</p><a href="<?php echo $manage_link; ?>" class="btn btn-primary"><i class="fas fa-arrow-left"></i> Back to Account Management</a></div></div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <div id="sidebarOverlay" class="sidebar-overlay" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('active');"></div>
</body>
</html>
