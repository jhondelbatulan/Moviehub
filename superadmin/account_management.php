<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/authorization.php';
require_once '../includes/csrf.php';

require_login();
require_role('super_admin');
require_permission('account_management.view');

$success = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action'])) {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token.';
    } else {
        $action = $_POST['action'];
        $user_table = $_POST['user_table'] ?? 'users';
        $target_id = intval($_POST['target_id'] ?? 0);

        try {
            if ($action === 'block') {
                block_account($pdo, $user_table, $target_id, 'Blocked by Super Admin');
                $success = 'Account blocked.';
            } elseif ($action === 'unblock') {
                unblock_account($pdo, $user_table, $target_id);
                $success = 'Account unblocked.';
            } elseif ($action === 'change_role') {
                $new_role = $_POST['new_role'] ?? '';
                $valid_roles = ['admin', 'super_admin'];
                if ($user_table === 'users') $valid_roles[] = 'user';
                if (in_array($new_role, $valid_roles)) {
                    $stmt = $pdo->prepare("UPDATE $user_table SET role = ? WHERE id = ?");
                    $stmt->execute([$new_role, $target_id]);
                    $success = 'Role updated to ' . $new_role . '.';
                } else {
                    $error = 'Invalid role.';
                }
            } elseif ($action === 'delete_account') {
                $reason = trim($_POST['reason'] ?? '');
                if (!check_user_password($pdo, 'admin_users', $_SESSION['admin_id'], $_POST['admin_password'] ?? '')) {
                    $error = 'You must enter your own current password to confirm the deletion.';
                } elseif (empty($reason)) { $error = 'A reason is required to delete an account.'; }
                elseif (empty($_FILES['document']['name']) || ($_FILES['document']['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
                    $error = 'A supporting document must be submitted before deleting an account.';
                } else {
                    $file = $_FILES['document'];
                    $allowed_mimes = ['application/pdf', 'image/jpeg', 'image/png', 'image/webp'];
                    $allowed_exts = ['pdf', 'jpg', 'jpeg', 'png', 'webp'];
                    $finfo = finfo_open(FILEINFO_MIME_TYPE);
                    $mime = finfo_file($finfo, $file['tmp_name']);
                    finfo_close($finfo);
                    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));

                    if (!in_array($mime, $allowed_mimes, true) || !in_array($ext, $allowed_exts, true)) {
                        $error = 'Invalid document type. Allowed: PDF, JPG, PNG, WEBP.';
                    } elseif ($file['size'] > (5 * 1024 * 1024)) {
                        $error = 'Document must not exceed 5MB.';
                    } else {
                        $upload_dir = __DIR__ . '/../assets/deletion_documents/';
                        if (!is_dir($upload_dir)) { @mkdir($upload_dir, 0777, true); }
                        $safe_name = preg_replace('/[^A-Za-z0-9._-]/', '_', $file['name']);
                        $stored_name = $user_table . '_' . $target_id . '_' . time() . '_' . uniqid() . '.' . $ext;
                        $dest = $upload_dir . $stored_name;
                        if (!move_uploaded_file($file['tmp_name'], $dest)) {
                            $error = 'Failed to upload document. Please try again.';
                        } else {
                            $target_name = '';
                            if ($user_table === 'users') {
                                $stmt = $pdo->prepare("SELECT first_name, last_name, username, email FROM users WHERE id = ?");
                            } else {
                                $stmt = $pdo->prepare("SELECT full_name, username, email FROM admin_users WHERE id = ?");
                            }
                            $stmt->execute([$target_id]);
                            $info = $stmt->fetch();
                            $target_name = $info ? ($info['full_name'] ?? ($info['first_name'].' '.$info['last_name'])) : 'Unknown';

                            $pdo->beginTransaction();
                            try {
                                $tables = [
                                    ["security_answers", "user_table = ? AND user_id = ?", [$user_table, $target_id]],
                                    ["registration_approvals", "user_id = ?", [$target_id]],
                                    ["rentals", "user_id = ?", [$target_id]],
                                    ["otp_codes", "user_table = ? AND user_id = ?", [$user_table, $target_id]],
                                    ["login_logs", "user_table = ? AND user_id = ?", [$user_table, $target_id]],
                                    ["account_status_history", "user_table = ? AND user_id = ?", [$user_table, $target_id]],
                                    ["user_permissions", "user_table = ? AND user_id = ?", [$user_table, $target_id]],
                                    ["deletion_requests", "target_table = ? AND target_id = ?", [$user_table, $target_id]],
                                ];
                                foreach ($tables as [$tbl, $where, $params]) {
                                    $pdo->prepare("DELETE FROM $tbl WHERE $where")->execute($params);
                                }

                                $stmt = $pdo->prepare("DELETE FROM $user_table WHERE id = ?");
                                $stmt->execute([$target_id]);

                                $pdo->prepare("INSERT INTO activity_logs (admin_id, admin_username, action, target_type, target_id, target_name, reason, ip_address) VALUES (?, ?, 'direct_delete', ?, ?, ?, ?, ?)")
                                    ->execute([$_SESSION['admin_id'], $_SESSION['admin_username'], $user_table, $target_id, $target_name, $reason, $_SERVER['REMOTE_ADDR'] ?? '']);

                                $pdo->prepare("INSERT INTO account_deletion_documents (deletion_request_id, target_table, target_id, file_path, original_name, file_size, mime_type, reason, submitted_by) VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?)")
                                    ->execute([$user_table, $target_id, $stored_name, $safe_name, $file['size'], $mime, $reason, $_SESSION['admin_id']]);

                                $pdo->commit();
                                $success = 'Account for ' . htmlspecialchars($target_name) . ' has been permanently deleted.';
                            } catch (PDOException $ex) {
                                $pdo->rollBack();
                                @unlink($dest);
                                error_log('[account_management] delete error: ' . $ex->getMessage());
                                $error = 'Failed to delete account.';
                            }
                        }
                    }
                }
            }
        } catch (PDOException $e) {
            error_log('[account_management] ' . $e->getMessage());
            $error = 'An error occurred.';
        }
    }
}

$tab = $_GET['tab'] ?? 'users';
$search = trim($_GET['search'] ?? '');
$role_filter = $_GET['role'] ?? '';
$status_filter = $_GET['status'] ?? '';
$page = max(1, intval($_GET['page'] ?? 1));
$per_page = RECORDS_PER_PAGE;

$users_data = [];
$total = 0;
$admins_data = [];
$total_admins = 0;

if ($tab === 'users') {
    $result = get_all_users_paginated($pdo, ['search' => $search, 'role' => $role_filter, 'status' => $status_filter], $per_page, $page);
    $users_data = $result['users'];
    $total = $result['total'];
    $pagination = $result['pagination'];
} else {
    $result = get_all_admins_paginated($pdo, ['search' => $search, 'role' => $role_filter, 'status' => $status_filter], $per_page, $page);
    $admins_data = $result['admins'];
    $total = $result['total'];
    $pagination = $result['pagination'];
}

generate_csrf_token();

if (isset($_GET['ajax']) && $_GET['ajax'] === 'privileges') {
    $atable = ($_GET['table'] ?? '') === 'admin_users' ? 'admin_users' : 'users';
    $aid = intval($_GET['id'] ?? 0);
    header('Content-Type: application/json');
    if ($aid <= 0) { echo json_encode(['ok' => false, 'message' => 'Invalid account.']); exit; }

    try {
        if ($atable === 'users') {
            $stmt = $pdo->prepare("SELECT id, username, email, CONCAT(first_name, ' ', last_name) AS full_name, role, account_status FROM users WHERE id = ?");
        } else {
            $stmt = $pdo->prepare("SELECT id, username, email, full_name, role, account_status FROM admin_users WHERE id = ?");
        }
        $stmt->execute([$aid]);
        $account = $stmt->fetch();
        if (!$account) { echo json_encode(['ok' => false, 'message' => 'Account not found.']); exit; }

        $essential_map = [
            'admin' => ['dashboard.view'],
            'user' => ['dashboard.view', 'movies.view', 'rentals.view', 'logs.view']
        ];
        $essential_fallback_ids = [
            'dashboard.view' => 1, 'movies.view' => 17, 'rentals.view' => 21, 'logs.view' => 27
        ];

        $baseline = [];
        $stmt = $pdo->prepare("SELECT permission_id, granted FROM role_permissions WHERE role = ?");
        $stmt->execute([$account['role']]);
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) { $baseline[(int)$row['permission_id']] = (bool)$row['granted']; }

        $overrides = [];
        $stmt = $pdo->prepare("SELECT permission_id, granted FROM user_permissions WHERE user_table = ? AND user_id = ?");
        $stmt->execute([$atable, $aid]);
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) { $overrides[(int)$row['permission_id']] = (bool)$row['granted']; }

        $essential_ids = [];
        $keys_for_role = $essential_map[$account['role']] ?? ['dashboard.view'];
        $ph = implode(',', array_fill(0, count($keys_for_role), '?'));
        $stmt = $pdo->prepare("SELECT id FROM permissions WHERE permission_key IN ($ph)");
        $stmt->execute($keys_for_role);
        $essential_ids = array_map('intval', $stmt->fetchAll(PDO::FETCH_COLUMN));
        foreach ($keys_for_role as $rk) {
            if (isset($essential_fallback_ids[$rk]) && !in_array($essential_fallback_ids[$rk], $essential_ids)) {
                $essential_ids[] = $essential_fallback_ids[$rk];
            }
        }

        $all_perms = $pdo->query("SELECT * FROM permissions ORDER BY category, permission_key")->fetchAll(PDO::FETCH_ASSOC);
        $list = [];
        foreach ($all_perms as $perm) {
            $pid = (int)$perm['id'];
            if ($account['role'] === 'super_admin') {
                $eff = true;
            } elseif (in_array($pid, $essential_ids, true)) {
                $eff = true;
            } else {
                $eff = array_key_exists($pid, $overrides) ? $overrides[$pid] : (isset($baseline[$pid]) ? $baseline[$pid] : false);
            }
            $list[] = [
                'id' => $pid,
                'key' => $perm['permission_key'],
                'desc' => (isset($perm['description']) && trim($perm['description']) !== '') ? trim($perm['description']) : $perm['permission_key'],
                'category' => (isset($perm['category']) && trim($perm['category']) !== '') ? trim($perm['category']) : 'general',
                'granted' => (bool)$eff
            ];
        }

        echo json_encode([
            'ok' => true,
            'account' => [
                'full_name' => $account['full_name'],
                'username' => $account['username'],
                'role' => $account['role'],
                'status' => $account['account_status']
            ],
            'permissions' => $list
        ]);
    } catch (PDOException $e) {
        echo json_encode(['ok' => false, 'message' => 'Failed to load privileges.']);
    }
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Account Management - MovieHub</title>
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
                    <div><h1 class="page-title">Account Management</h1><p class="page-subtitle">Manage all user and admin accounts (<?php echo number_format($total); ?> records)</p></div>
                </div>
            </div>

            <div class="content-body">
                <?php if ($success): ?><div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($success); ?></div><?php endif; ?>
                <?php if ($error): ?><div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div><?php endif; ?>

                <div class="flex gap-3" style="margin-bottom:1rem;">
                    <a href="?tab=users" class="btn <?php echo $tab==='users'?'btn-primary':'btn-outline'; ?>">Users (<?php echo $tab==='users'?$total:'..'; ?>)</a>
                    <a href="?tab=admins" class="btn <?php echo $tab==='admins'?'btn-primary':'btn-outline'; ?>">Admins (<?php echo $tab==='admins'?$total:'..'; ?>)</a>
                </div>

                <div class="card" style="margin-bottom:1.5rem;">
                    <div class="card-body" style="padding:1rem 1.5rem;">
                        <form method="GET" action="" class="flex items-center gap-3" style="flex-wrap:wrap;">
                            <input type="hidden" name="tab" value="<?php echo htmlspecialchars($tab); ?>">
                            <div class="form-group" style="flex:1;min-width:180px;margin-bottom:0;"><input type="text" name="search" class="form-control" placeholder="Search name, username, email..." value="<?php echo htmlspecialchars($search); ?>"></div>
                            <div class="form-group" style="flex:0 0 120px;margin-bottom:0;"><select name="role" class="form-control"><option value="">All Roles</option>
                                <?php if ($tab==='users'): ?>
                                    <option value="user" <?php echo $role_filter==='user'?'selected':''; ?>>User</option>
                                <?php else: ?>
                                    <option value="admin" <?php echo $role_filter==='admin'?'selected':''; ?>>Admin</option>
                                    <option value="super_admin" <?php echo $role_filter==='super_admin'?'selected':''; ?>>Super Admin</option>
                                <?php endif; ?>
                            </select></div>
                            <div class="form-group" style="flex:0 0 120px;margin-bottom:0;"><select name="status" class="form-control"><option value="">All Status</option>
                                <option value="active" <?php echo $status_filter==='active'?'selected':''; ?>>Active</option>
                                <option value="approved" <?php echo $status_filter==='approved'?'selected':''; ?>>Approved</option>
                                <option value="inactive" <?php echo $status_filter==='inactive'?'selected':''; ?>>Inactive</option>
                                <option value="pending" <?php echo $status_filter==='pending'?'selected':''; ?>>Pending</option>
                                <option value="blocked" <?php echo $status_filter==='blocked'?'selected':''; ?>>Blocked</option>
                                <option value="rejected" <?php echo $status_filter==='rejected'?'selected':''; ?>>Rejected</option>
                            </select></div>
                            <button type="submit" class="btn btn-primary btn-sm"><i class="fas fa-search"></i></button>
                            <a href="?tab=<?php echo htmlspecialchars($tab); ?>" class="btn btn-outline btn-sm"><i class="fas fa-times"></i></a>
                        </form>
                    </div>
                </div>

                <div class="card">
                    <div class="table-responsive">
                        <table class="table">
                            <thead><tr>
                                <th>ID</th><th>Name</th><th>Username</th><th>Email</th><th>Role</th><th>Status</th><th>Actions</th>
                            </tr></thead>
                            <tbody>
<?php if ($tab === 'users'): ?>
<?php foreach ($users_data as $u): ?>
                                <tr>
                                    <td><small><?php echo htmlspecialchars($u['employee_id'] ?? $u['id']); ?></small></td>
                                    <td><strong><?php echo htmlspecialchars($u['first_name'].' '.$u['last_name']); ?></strong></td>
                                    <td><?php echo htmlspecialchars($u['username']); ?></td>
                                    <td><small><?php echo htmlspecialchars($u['email']); ?></small></td>
                                    <td><?php echo render_role_badge($u['role'] ?? 'user'); ?></td>
                                    <td><?php echo render_status_badge($u['account_status']); ?></td>
                                    <td>
                                        <div class="table-actions">
                                            <a href="edit_user.php?id=<?php echo $u['id']; ?>" class="btn btn-sm btn-outline" title="Edit"><i class="fas fa-edit"></i></a>
                                            <button type="button" class="btn btn-sm btn-outline" title="View Privileges" onclick="openPrivModal('users', <?php echo $u['id']; ?>, '<?php echo htmlspecialchars(addslashes($u['first_name'].' '.$u['last_name'])); ?>')"><i class="fas fa-shield-alt"></i></button>
                                            <?php if ($u['account_status'] !== 'blocked'): ?>
                                                <form method="POST" action="" style="display:inline;" onsubmit="return confirm('Block this user?');">
                                                    <?php csrf_token_input(); ?>
                                                    <input type="hidden" name="action" value="block">
                                                    <input type="hidden" name="user_table" value="users">
                                                    <input type="hidden" name="target_id" value="<?php echo $u['id']; ?>">
                                                    <button class="btn btn-sm btn-outline-danger" title="Block"><i class="fas fa-ban"></i></button>
                                                </form>
                                            <?php else: ?>
                                                <form method="POST" action="" style="display:inline;">
                                                    <?php csrf_token_input(); ?>
                                                    <input type="hidden" name="action" value="unblock">
                                                    <input type="hidden" name="user_table" value="users">
                                                    <input type="hidden" name="target_id" value="<?php echo $u['id']; ?>">
                                                    <button class="btn btn-sm btn-success" title="Unblock"><i class="fas fa-unlock"></i></button>
                                                </form>
                                            <?php endif; ?>
                                            <form method="POST" action="" style="display:inline;" enctype="multipart/form-data" class="delete-form" data-name="<?php echo htmlspecialchars($u['first_name'].' '.$u['last_name']); ?>" onsubmit="return submitDelete(this,'users',<?php echo $u['id']; ?>);">
                                                <?php csrf_token_input(); ?>
                                                <input type="hidden" name="action" value="delete_account">
                                                <input type="hidden" name="user_table" value="users">
                                                <input type="hidden" name="target_id" value="<?php echo $u['id']; ?>">
                                                <button type="button" class="btn btn-sm btn-danger" title="Delete Account" onclick="openDeleteModal(this)"><i class="fas fa-trash"></i></button>
                                            </form>
                                        </div>
                                    </td>
                                </tr>
<?php endforeach; ?>
<?php else: ?>
<?php foreach ($admins_data as $a): ?>
                                <tr>
                                    <td><small><?php echo htmlspecialchars($a['employee_id'] ?? $a['id']); ?></small></td>
                                    <td><strong><?php echo htmlspecialchars($a['full_name']); ?></strong></td>
                                    <td><?php echo htmlspecialchars($a['username']); ?></td>
                                    <td><small><?php echo htmlspecialchars($a['email']); ?></small></td>
                                    <td><?php echo render_role_badge($a['role']); ?></td>
                                    <td><?php echo render_status_badge($a['account_status']); ?></td>
                                    <td>
                                        <div class="table-actions">
                                            <?php if ($a['id'] != $_SESSION['admin_id']): ?>
                                                <a href="edit_admin.php?id=<?php echo $a['id']; ?>" class="btn btn-sm btn-outline" title="Edit"><i class="fas fa-edit"></i></a>
                                                <button type="button" class="btn btn-sm btn-outline" title="View Privileges" onclick="openPrivModal('admin_users', <?php echo $a['id']; ?>, '<?php echo htmlspecialchars(addslashes($a['full_name'])); ?>')"><i class="fas fa-shield-alt"></i></button>
                                                <?php if ($a['account_status'] !== 'blocked'): ?>
                                                    <form method="POST" action="" style="display:inline;" onsubmit="return confirm('Block this admin?');">
                                                        <?php csrf_token_input(); ?>
                                                        <input type="hidden" name="action" value="block">
                                                        <input type="hidden" name="user_table" value="admin_users">
                                                        <input type="hidden" name="target_id" value="<?php echo $a['id']; ?>">
                                                        <button class="btn btn-sm btn-outline-danger" title="Block"><i class="fas fa-ban"></i></button>
                                                    </form>
                                                <?php else: ?>
                                                    <form method="POST" action="" style="display:inline;">
                                                        <?php csrf_token_input(); ?>
                                                        <input type="hidden" name="action" value="unblock">
                                                        <input type="hidden" name="user_table" value="admin_users">
                                                        <input type="hidden" name="target_id" value="<?php echo $a['id']; ?>">
                                                        <button class="btn btn-sm btn-success" title="Unblock"><i class="fas fa-unlock"></i></button>
                                                    </form>
                                                <?php endif; ?>
                                                <form method="POST" action="" style="display:inline;" enctype="multipart/form-data" class="delete-form" data-name="<?php echo htmlspecialchars($a['full_name']); ?>" onsubmit="return submitDelete(this,'admin_users',<?php echo $a['id']; ?>);">
                                                    <?php csrf_token_input(); ?>
                                                    <input type="hidden" name="action" value="delete_account">
                                                    <input type="hidden" name="user_table" value="admin_users">
                                                    <input type="hidden" name="target_id" value="<?php echo $a['id']; ?>">
                                                    <button type="button" class="btn btn-sm btn-danger" title="Delete Account" onclick="openDeleteModal(this)"><i class="fas fa-trash"></i></button>
                                                </form>
                                            <?php else: ?>
                                                <a href="edit_admin.php?id=<?php echo $a['id']; ?>" class="btn btn-sm btn-outline" title="Edit"><i class="fas fa-edit"></i></a>
                                                <span class="text-muted text-sm">You</span>
                                            <?php endif; ?>
                                        </div>
                                    </td>
                                </tr>
<?php endforeach; ?>
<?php endif; ?>
<?php if (($tab==='users' && empty($users_data)) || ($tab==='admins' && empty($admins_data))): ?>
                                <tr><td colspan="7" class="text-center text-muted" style="padding:2rem;">No accounts found.</td></tr>
<?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>

                <?php if ($pagination['total_pages'] > 1): ?>
                <div class="pagination" style="justify-content:center;margin-top:1.5rem;">
                    <?php
                    $bp = $_GET; $bp['tab'] = $tab;
                    if ($page > 1) { $bp['page']=$page-1; echo '<a href="?'.http_build_query($bp).'" class="btn btn-outline btn-sm"><i class="fas fa-chevron-left"></i></a>'; }
                    $s = max(1,$page-2); $e = min($pagination['total_pages'],$page+2);
                    for ($i=$s;$i<=$e;$i++) { $bp['page']=$i; $c=($i===$page)?'btn-primary':'btn-outline'; echo '<a href="?'.http_build_query($bp).'" class="btn '.$c.' btn-sm">'.$i.'</a>'; }
                    if ($page < $pagination['total_pages']) { $bp['page']=$page+1; echo '<a href="?'.http_build_query($bp).'" class="btn btn-outline btn-sm"><i class="fas fa-chevron-right"></i></a>'; }
                    ?>
                </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <div id="deleteModal" class="modal" style="display:none;">
        <div class="modal-content" style="max-width:520px;">
            <div class="modal-header">
                <h3 class="modal-title"><i class="fas fa-trash" style="color:var(--danger);"></i> Delete Account</h3>
                <button type="button" class="modal-close" onclick="closeDeleteModal()" style="background:none;border:none;font-size:1.25rem;color:var(--muted);cursor:pointer;">&times;</button>
            </div>
            <div class="modal-body">
                <div class="alert alert-danger" style="font-size:0.8125rem;">
                    <i class="fas fa-exclamation-triangle"></i> You are about to permanently delete <strong id="delTargetName"></strong>. This cannot be undone.
                </div>
                <div class="alert alert-warning" style="font-size:0.8125rem;">
                    <i class="fas fa-file-upload"></i> A supporting <strong>document (PDF, JPG, PNG, WEBP; max 5MB)</strong> and a reason are required before the account can be deleted.
                </div>
                <div class="form-group">
                    <label for="delReason">Reason for Deletion *</label>
                    <textarea id="delReason" class="form-control" rows="3" placeholder="Explain why this account must be deleted..."></textarea>
                </div>
                <div class="form-group">
                    <label for="delDocument">Supporting Document *</label>
                    <input type="file" id="delDocument" class="form-control" accept=".pdf,.jpg,.jpeg,.png,.webp">
                    <small style="font-size:0.6875rem;color:var(--muted);">Attach the document justifying the deletion.</small>
                </div>
                <div class="form-group">
                    <label for="delPassword">Your Password (to confirm deletion) *</label>
                    <input type="password" id="delPassword" class="form-control" autocomplete="off" placeholder="Enter YOUR current password to confirm">
                </div>
                <div id="delValidation" class="alert alert-danger" style="display:none;font-size:0.8125rem;"></div>
            </div>
            <div class="modal-footer" style="display:flex;gap:0.5rem;padding:1rem 1.5rem;border-top:1px solid var(--border);">
                <button type="button" class="btn btn-outline" style="flex:1;" onclick="closeDeleteModal()">Cancel</button>
                <button type="button" class="btn btn-danger" style="flex:1;" onclick="confirmDelete()"><i class="fas fa-trash"></i> Confirm &amp; Delete</button>
            </div>
        </div>
    </div>

    <div id="privModal" class="modal" style="display:none;">
        <div class="modal-content" style="max-width:640px;">
            <div class="modal-header">
                <h3 class="modal-title"><i class="fas fa-shield-alt" style="color:var(--primary);"></i> Account Privileges</h3>
                <button type="button" class="modal-close" onclick="closePrivModal()" style="background:none;border:none;font-size:1.25rem;color:var(--muted);cursor:pointer;">&times;</button>
            </div>
            <div class="modal-body" style="padding-top:0.5rem;">
                <div id="privAccountInfo" style="display:flex;align-items:center;gap:0.75rem;margin-bottom:1rem;"></div>
                <div id="privLoading" style="text-align:center;padding:1.5rem;color:var(--muted);"><i class="fas fa-spinner fa-spin"></i> Loading privileges...</div>
                <div id="privCard" style="display:none;">
                    <div class="card" style="border:1px solid var(--border);">
                        <div class="card-body" style="padding:1rem;max-height:420px;overflow-y:auto;">
                            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem;">
                                <strong style="font-size:0.8125rem;">Permissions</strong>
                                <small id="privSummary" class="text-muted"></small>
                            </div>
                            <div id="privList"></div>
                        </div>
                    </div>
                </div>
                <div id="privError" class="alert alert-danger" style="display:none;font-size:0.8125rem;margin-top:0.5rem;"></div>
            </div>
            <div class="modal-footer" style="display:flex;gap:0.5rem;padding:1rem 1.5rem;border-top:1px solid var(--border);">
                <button type="button" class="btn btn-outline" style="flex:1;" onclick="closePrivModal()">Close</button>
            </div>
        </div>
    </div>

    <div id="sidebarOverlay" class="sidebar-overlay" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('active');"></div>

    <script>
        var activeDeleteForm = null;
        function openDeleteModal(btn) {
            activeDeleteForm = btn.closest('form');
            document.getElementById('delTargetName').textContent = activeDeleteForm.getAttribute('data-name');
            document.getElementById('delReason').value = '';
            document.getElementById('delDocument').value = '';
            document.getElementById('delPassword').value = '';
            document.getElementById('delValidation').style.display = 'none';
            document.getElementById('deleteModal').style.display = 'flex';
        }
        function closeDeleteModal() { document.getElementById('deleteModal').style.display = 'none'; activeDeleteForm = null; }
        function confirmDelete() {
            if (!activeDeleteForm) return;
            var form = activeDeleteForm;
            var reason = document.getElementById('delReason').value.trim();
            var file = document.getElementById('delDocument').files[0];
            var password = document.getElementById('delPassword').value;
            var val = document.getElementById('delValidation');
            if (!reason) { val.textContent = 'A reason is required.'; val.style.display = 'block'; return; }
            if (!file) { val.textContent = 'A supporting document is required.'; val.style.display = 'block'; return; }
            if (!password) { val.textContent = 'You must enter your current password to confirm the deletion.'; val.style.display = 'block'; return; }
            var okExt = /\.(pdf|jpg|jpeg|png|webp)$/i.test(file.name);
            if (!okExt) { val.textContent = 'Invalid document type. Allowed: PDF, JPG, PNG, WEBP.'; val.style.display = 'block'; return; }
            if (file.size > 5*1024*1024) { val.textContent = 'Document must not exceed 5MB.'; val.style.display = 'block'; return; }
            val.style.display = 'none';
            if (!confirm('Permanently delete ' + form.getAttribute('data-name') + '? This cannot be undone.')) return;

            var reasonInput = document.createElement('textarea');
            reasonInput.name = 'reason'; reasonInput.value = reason; reasonInput.style.display = 'none';
            form.appendChild(reasonInput);
            var pwdInput = document.createElement('input');
            pwdInput.type = 'hidden'; pwdInput.name = 'admin_password'; pwdInput.value = password;
            form.appendChild(pwdInput);
            var fileInput = document.createElement('input');
            fileInput.type = 'file'; fileInput.name = 'document';
            var dt = new DataTransfer(); dt.items.add(file); fileInput.files = dt.files; fileInput.style.display = 'none';
            form.appendChild(fileInput);
            closeDeleteModal();
            form.submit();
        }

        function openPrivModal(table, id, name) {
            document.getElementById('privCard').style.display = 'none';
            document.getElementById('privError').style.display = 'none';
            document.getElementById('privLoading').style.display = 'block';
            document.getElementById('privList').innerHTML = '';
            document.getElementById('privAccountInfo').innerHTML = '<div class="avatar avatar-sm" style="background:var(--primary);color:white;flex-shrink:0;">' + (name ? name.charAt(0).toUpperCase() : '?') + '</div><div><strong>' + escapeHtml(name) + '</strong><br><small class="text-muted" id="privRole">...</small></div>';
            document.getElementById('privModal').style.display = 'flex';
            fetch('account_management.php?ajax=privileges&table=' + encodeURIComponent(table) + '&id=' + encodeURIComponent(id))
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    document.getElementById('privLoading').style.display = 'none';
                    if (!data.ok) {
                        var er = document.getElementById('privError');
                        er.textContent = data.message || 'Failed to load privileges.';
                        er.style.display = 'block';
                        return;
                    }
                    var role = data.account.role;
                    var roleLabel = role === 'super_admin' ? '<span class="badge badge-warning">Super Admin</span>' : (role === 'admin' ? '<span class="badge badge-info">Admin</span>' : '<span class="badge badge-success">User</span>');
                    document.getElementById('privRole').innerHTML = roleLabel;
                    var granted = 0;
                    var html = '';
                    data.permissions.forEach(function (p) {
                        if (p.granted) granted++;
                        html += '<div class="priv-row" style="display:flex;align-items:center;gap:0.5rem;padding:0.35rem 0.5rem;border-radius:var(--radius);font-size:0.8125rem;' + (p.granted ? 'background:rgba(40,199,111,0.08);' : 'background:rgba(255,77,79,0.06);') + '">'
                            + '<span style="color:' + (p.granted ? 'var(--success)' : 'var(--danger)') + ';flex-shrink:0;"><i class="fas fa-' + (p.granted ? 'check-circle' : 'times-circle') + '"></i></span>'
                            + '<span style="flex:1;">' + escapeHtml(p.desc) + '</span>'
                            + '<small class="text-muted" style="flex-shrink:0;font-size:0.6875rem;">' + (p.granted ? 'Allowed' : 'Denied') + '</small>'
                            + '</div>';
                    });
                    document.getElementById('privList').innerHTML = html;
                    document.getElementById('privSummary').textContent = granted + ' of ' + data.permissions.length + ' granted';
                    document.getElementById('privCard').style.display = 'block';
                })
                .catch(function () {
                    document.getElementById('privLoading').style.display = 'none';
                    var er = document.getElementById('privError');
                    er.textContent = 'Failed to load privileges.';
                    er.style.display = 'block';
                });
        }
        function closePrivModal() { document.getElementById('privModal').style.display = 'none'; }
        function escapeHtml(str) {
            var div = document.createElement('div');
            div.textContent = str == null ? '' : String(str);
            return div.innerHTML;
        }
    </script>
</body>
</html>
