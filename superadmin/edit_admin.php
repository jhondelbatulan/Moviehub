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
    if ($editing_admin_id !== intval($_SESSION['admin_id'] ?? 0)) {
        flash_message('error', 'You can only edit your own profile.');
        redirect('../admin/dashboard.php');
    }
    require_role('admin');
}

$admin_id = $editing_admin_id;
$error = '';
$is_owner = (intval($_SESSION['admin_id'] ?? 0) === $admin_id);

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if ($admin_id <= 0) {
        $error = 'Invalid admin ID.';
    } elseif (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token.';
    } elseif (!check_user_password($pdo, 'admin_users', $_SESSION['admin_id'], $_POST['editor_password'] ?? '')) {
        $error = 'You must enter your own current password to verify this change.';
    } else {
        $full_name = trim($_POST['full_name'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $phone = trim($_POST['phone'] ?? '');
        $address = trim($_POST['address'] ?? '');
        $role = $_POST['role'] ?? '';
        $account_status = $_POST['account_status'] ?? '';

        $ok = true;
        if ($is_owner) {
            $ok = $ok && ($full_name !== '' && $email !== '');
            if ($ok && !filter_var($email, FILTER_VALIDATE_EMAIL)) { $error = 'Invalid email address.'; $ok = false; }
        } else {
            if (!in_array($role, ['admin', 'super_admin'], true)) { $error = 'Invalid role.'; $ok = false; }
            if ($ok && !in_array($account_status, ['active', 'blocked', 'inactive'], true)) { $error = 'Invalid account status.'; $ok = false; }
        }

        if ($ok) {
            try {
                if ($is_owner) {
                    $stmt = $pdo->prepare("SELECT id FROM admin_users WHERE email = ? AND id != ?");
                    $stmt->execute([$email, $admin_id]);
                    if ($stmt->fetch()) {
                        $error = 'That email address is already used by another account.';
                        $ok = false;
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
                    $stmt = $pdo->prepare("UPDATE admin_users SET full_name = ?, email = ?, phone = ?, address = ? WHERE id = ?");
                    $stmt->execute([
                        $full_name,
                        $email,
                        $phone !== '' ? $phone : null,
                        $address !== '' ? $address : null,
                        $admin_id
                    ]);
                } else {
                    $stmt = $pdo->prepare("UPDATE admin_users SET role = ?, account_status = ? WHERE id = ?");
                    $stmt->execute([$role, $account_status, $admin_id]);
                }

                if ($is_owner) {
                    $sq1_id = (int)($_POST['sq1_id'] ?? 0);
                    $sq2_id = (int)($_POST['sq2_id'] ?? 0);
                    $sq3_id = (int)($_POST['sq3_id'] ?? 0);
                    $sq1_answer = trim($_POST['sq1_answer'] ?? '');
                    $sq2_answer = trim($_POST['sq2_answer'] ?? '');
                    $sq3_answer = trim($_POST['sq3_answer'] ?? '');
                    $sq_ids = [$sq1_id, $sq2_id, $sq3_id];
                    $sq_answers = [$sq1_answer, $sq2_answer, $sq3_answer];

                    if (!(in_array('', $sq_answers, true)) && !(count(array_unique($sq_ids)) !== 3)) {
                        $valid_ids = array_filter($sq_ids, function ($v) { return $v > 0; });
                        if (count($valid_ids) === 3) {
                            $del = $pdo->prepare("DELETE FROM security_answers WHERE user_table = 'admin_users' AND user_id = ?");
                            $del->execute([$admin_id]);
                            $ins = $pdo->prepare("INSERT INTO security_answers (user_table, user_id, question_id, answer_hash) VALUES ('admin_users', ?, ?, ?)");
                            for ($i = 0; $i < 3; $i++) {
                                $answer = strtolower(trim($sq_answers[$i]));
                                $answer_hash = password_hash($answer, PASSWORD_DEFAULT);
                                $ins->execute([$admin_id, $sq_ids[$i], $answer_hash]);
                            }
                        }
                    }
                }

                redirect('edit_admin.php?id=' . $admin_id . '&updated=1');
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
    $secret_questions = $pdo->query("SELECT id, question_text FROM secret_questions ORDER BY sort_order, id")->fetchAll(PDO::FETCH_ASSOC);
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
            <div class="sidebar-header"><a href="dashboard.php" class="sidebar-logo"><i class="fas fa-film"></i><span>MovieHub</span></a></div>
            <nav class="sidebar-nav">
                <div class="sidebar-section"><div class="sidebar-section-title">Overview</div>
                    <a href="dashboard.php" class="sidebar-link"><i class="fas fa-tachometer-alt"></i><span>Dashboard</span></a>
                </div>
                <div class="sidebar-section"><div class="sidebar-section-title">User Management</div>
                    <a href="account_management.php" class="sidebar-link active"><i class="fas fa-users-cog"></i><span>Account Management</span></a>
                    <a href="create_account.php" class="sidebar-link"><i class="fas fa-user-plus"></i><span>Create Account</span></a>
                    <a href="privilege_management.php" class="sidebar-link"><i class="fas fa-shield-alt"></i><span>Privileges</span></a>
                    <a href="../admin/registration_approval.php" class="sidebar-link"><i class="fas fa-user-check"></i><span>Registration Approvals</span></a>
                    <a href="deletion_requests.php" class="sidebar-link"><i class="fas fa-user-minus"></i><span>Deletion Requests</span></a>
                </div>
                <div class="sidebar-section"><div class="sidebar-section-title">Activity</div>
                    <a href="../admin/login_logs.php" class="sidebar-link"><i class="fas fa-history"></i><span>Login Logs</span></a>
                </div>
                <div class="sidebar-section"><div class="sidebar-section-title">Account</div>
                    <a href="../client/logout.php" class="sidebar-link"><i class="fas fa-sign-out-alt"></i><span>Logout</span></a>
                </div>
            </nav>
            <a href="edit_admin.php?id=<?php echo (int)$_SESSION['admin_id']; ?>" class="sidebar-user" style="display:flex;align-items:center;gap:0.75rem;padding:0.75rem 1rem;color:inherit;text-decoration:none;transition:background 0.15s;cursor:pointer;" title="Edit my profile">
                <div class="avatar avatar-sm" style="background:var(--primary);color:white;"><?php echo strtoupper(substr($_SESSION['admin_full_name'], 0, 1)); ?></div>
                <div class="sidebar-user-info">
                    <div class="sidebar-user-name"><?php echo htmlspecialchars($_SESSION['admin_full_name']); ?></div>
                    <div class="sidebar-user-role" style="color:var(--primary);font-weight:600;">Super Admin</div>
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
                    <a href="account_management.php" class="btn btn-outline btn-sm"><i class="fas fa-arrow-left"></i> Back to Account Management</a>
                </div>

                <div class="card" style="max-width:700px;">
                    <div class="card-header"><h3 class="card-title"><i class="fas fa-user-shield"></i> Administrator Details</h3></div>
                    <div class="card-body">
                        <form method="POST" action="">
                            <?php csrf_token_input(); ?>
                            <div style="display:grid;grid-template-columns:1fr 1fr;gap:0 1rem;">
                                <div class="form-group"><label>Employee ID</label><input type="text" class="form-control" value="<?php echo htmlspecialchars($admin['employee_id'] ?? ''); ?>" readonly disabled></div>
                                <div class="form-group"><label>Username</label><input type="text" class="form-control" value="<?php echo htmlspecialchars($admin['username']); ?>" readonly disabled></div>
                            </div>

                            <?php if ($is_owner): ?>
                            <div class="form-group"><label>Full Name *</label><input type="text" name="full_name" class="form-control" required maxlength="100" value="<?php echo htmlspecialchars($admin['full_name']); ?>"></div>
                            <div class="form-group"><label>Email *</label><input type="email" name="email" class="form-control" required maxlength="100" value="<?php echo htmlspecialchars($admin['email']); ?>"></div>
                            <div class="form-group"><label>Phone</label><input type="tel" name="phone" class="form-control" maxlength="20" value="<?php echo htmlspecialchars($admin['phone'] ?? ''); ?>"></div>
                            <div class="form-group"><label>Address</label><input type="text" name="address" class="form-control" maxlength="255" value="<?php echo htmlspecialchars($admin['address'] ?? ''); ?>"></div>
                            <?php else: ?>
                            <div class="form-group"><label>Full Name</label><input type="text" class="form-control" value="<?php echo htmlspecialchars($admin['full_name']); ?>" readonly disabled></div>
                            <div class="form-group"><label>Email</label><input type="text" class="form-control" value="<?php echo htmlspecialchars($admin['email']); ?>" readonly disabled></div>
                            <div class="form-group"><label>Phone</label><input type="text" class="form-control" value="<?php echo htmlspecialchars($admin['phone'] ?? ''); ?>" readonly disabled></div>
                            <div class="form-group"><label>Address</label><input type="text" class="form-control" value="<?php echo htmlspecialchars($admin['address'] ?? ''); ?>" readonly disabled></div>
                            <div class="alert alert-info" style="font-size:0.8125rem;"><i class="fas fa-info-circle"></i> Personal information can only be changed by the account owner from their own profile.</div>
                            <?php endif; ?>

                            <?php if ($is_owner): ?>
                            <div style="display:grid;grid-template-columns:1fr 1fr;gap:0 1rem;">
                                <div class="form-group"><label>Role</label><input type="text" class="form-control" value="<?php echo ($admin['role'] ?? 'admin') === 'super_admin' ? 'Super Admin' : 'Admin'; ?>" readonly disabled></div>
                                <div class="form-group"><label>Account Status</label><input type="text" class="form-control" value="<?php echo ucfirst($admin['account_status'] ?? 'active'); ?>" readonly disabled></div>
                            </div>
                            <?php else: ?>
                            <div style="display:grid;grid-template-columns:1fr 1fr;gap:0 1rem;">
                                <div class="form-group"><label>Role *</label>
                                    <select name="role" class="form-control" required>
                                        <option value="admin" <?php echo ($admin['role'] ?? 'admin') === 'admin' ? 'selected' : ''; ?>>Admin</option>
                                        <option value="super_admin" <?php echo ($admin['role'] ?? '') === 'super_admin' ? 'selected' : ''; ?>>Super Admin</option>
                                    </select>
                                </div>
                                <div class="form-group"><label>Account Status *</label>
                                    <select name="account_status" class="form-control" required>
                                        <option value="active" <?php echo ($admin['account_status'] ?? '') === 'active' ? 'selected' : ''; ?>>Active</option>
                                        <option value="blocked" <?php echo ($admin['account_status'] ?? '') === 'blocked' ? 'selected' : ''; ?>>Blocked</option>
                                        <option value="inactive" <?php echo ($admin['account_status'] ?? '') === 'inactive' ? 'selected' : ''; ?>>Inactive</option>
                                    </select>
                                </div>
                            </div>
                            <?php endif; ?>

                            <?php if ($is_owner): ?>
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
                                <a href="account_management.php" class="btn btn-outline">Cancel</a>
                            </div>
                        </form>
                        <script>
                        (function () {
                            var selects = document.getElementsByClassName('sq-select');
                            function refresh() {
                                for (var i = 0; i < selects.length; i++) {
                                    var cur = selects[i].value;
                                    for (var j = 0; j < selects.length; j++) {
                                        if (i === j) continue;
                                        var opts = selects[j].options;
                                        for (var k = 0; k < opts.length; k++) {
                                            opts[k].disabled = (opts[k].value !== '' && opts[k].value !== '0' && opts[k].value === cur);
                                        }
                                    }
                                }
                            }
                            for (var i = 0; i < selects.length; i++) {
                                selects[i].addEventListener('change', refresh);
                            }
                            refresh();
                        })();
                        </script>
                    </div>
                </div>
                <?php else: ?>
                <div class="card" style="max-width:700px;"><div class="card-body text-center" style="padding:2rem;"><p class="text-muted">No admin selected.</p><a href="account_management.php" class="btn btn-primary"><i class="fas fa-arrow-left"></i> Back to Account Management</a></div></div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <div id="sidebarOverlay" class="sidebar-overlay" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('active');"></div>
</body>
</html>
