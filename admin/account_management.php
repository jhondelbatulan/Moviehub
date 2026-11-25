<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/authorization.php';
require_once '../includes/csrf.php';

require_login();
require_role(['admin', 'super_admin']);
require_permission('account_management.view');

$success = '';
$error = '';
$is_superadmin = (($_SESSION['admin_role'] ?? '') === 'super_admin');

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action'])) {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token.';
    } else {
        $action = $_POST['action'];
        $target_id = intval($_POST['target_id'] ?? 0);
        $user_table = ($_POST['user_table'] ?? 'users') === 'admin_users' ? 'admin_users' : 'users';

        try {
            $target_is_superadmin = false;
            if ($user_table === 'admin_users') {
                $role_stmt = $pdo->prepare("SELECT role FROM admin_users WHERE id = ?");
                $role_stmt->execute([$target_id]);
                $target_is_superadmin = ($role_stmt->fetchColumn() === 'super_admin');
            }
            if (($_POST['admin_password'] ?? '') === '') {
                $error = 'Please enter your current password to confirm this action.';
            } elseif (!check_user_password($pdo, 'admin_users', $_SESSION['admin_id'], $_POST['admin_password'] ?? '')) {
                $error = 'Inputted password is wrong.';
            } elseif (!$is_superadmin && $target_is_superadmin) {
                $error = 'You do not have permission to manage super admin accounts.';
            } elseif ($action === 'block') {
                $perm_ok = ($user_table === 'admin_users') ? check_permission($pdo, 'admin_users', $_SESSION['admin_id'], 'admins.block') : true;
                if (!$perm_ok) {
                    $error = 'You do not have permission for this action.';
                } elseif ($is_superadmin) {
                    block_account($pdo, $user_table, $target_id, 'Blocked by Super Admin');
                    log_audit($pdo, 'block_account', $user_table, $target_id, null, ($user_table === 'users' ? 'User' : 'Admin') . " account #{$target_id} blocked");
                    $success = 'Account blocked.';
                } else {
                    $reason = trim($_POST['reason'] ?? '');
                    if (empty($reason)) {
                        $error = 'A reason is required to block an account.';
                    } elseif (empty($_FILES['block_document']['name']) || ($_FILES['block_document']['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
                        $error = 'A supporting document is required before requesting a block.';
                    } else {
                        $file = $_FILES['block_document'];
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
                            $upload_dir = __DIR__ . '/../assets/block_request_documents/';
                            if (!is_dir($upload_dir)) { @mkdir($upload_dir, 0777, true); }
                            $safe_name = preg_replace('/[^A-Za-z0-9._-]/', '_', $file['name']);
                            $stored_name = $user_table . '_' . $target_id . '_' . time() . '_' . uniqid() . '.' . $ext;
                            $dest = $upload_dir . $stored_name;
                            if (!move_uploaded_file($file['tmp_name'], $dest)) {
                                $error = 'Failed to upload document. Please try again.';
                            } else {
                                $pdo->beginTransaction();
                                try {
                                    if ($user_table === 'users') {
                                        $stmt = $pdo->prepare("SELECT CONCAT(first_name,' ',last_name) AS full_name, username, email, role FROM users WHERE id = ?");
                                    } else {
                                        $stmt = $pdo->prepare("SELECT full_name, username, email, role FROM admin_users WHERE id = ?");
                                    }
                                    $stmt->execute([$target_id]);
                                    $info = $stmt->fetch();
                                    $target_name = $info ? ($info['full_name'] ?? 'Unknown') : 'Unknown';

                                    $pdo->prepare("INSERT INTO block_requests (target_table, target_id, target_name, target_email, target_role, requested_by_id, requested_by_name, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
                                        ->execute([$user_table, $target_id, $target_name, $info['email'] ?? null, $info['role'] ?? null, $_SESSION['admin_id'], $_SESSION['admin_full_name'] ?? '', $reason]);
                                    $req_id = (int)$pdo->lastInsertId();

                                    $pdo->prepare("INSERT INTO block_request_documents (block_request_id, target_table, target_id, file_path, original_name, file_size, mime_type, reason, submitted_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
                                        ->execute([$req_id, $user_table, $target_id, $stored_name, $safe_name, $file['size'], $mime, $reason, $_SESSION['admin_id']]);

                                    log_audit($pdo, 'block_request_created', $user_table, $target_id, $target_name, 'Block request submitted for Super Admin review: ' . $reason);
                                    $pdo->commit();
                                    $success = 'Block request for ' . htmlspecialchars($target_name) . ' has been sent to the Super Admin for approval. The account is not blocked yet.';
                                } catch (PDOException $e) {
                                    $pdo->rollBack();
                                    @unlink($dest);
                                    error_log('[account_management] block request error: ' . $e->getMessage());
                                    $error = 'Failed to submit the block request.';
                                }
                            }
                        }
                    }
                }
            } elseif ($action === 'unblock') {
                $perm_ok = ($user_table === 'admin_users') ? check_permission($pdo, 'admin_users', $_SESSION['admin_id'], 'admins.unblock') : true;
                if (!$perm_ok) {
                    $error = 'You do not have permission for this action.';
                } else {
                    unblock_account($pdo, $user_table, $target_id);
                    log_audit($pdo, 'unblock_account', $user_table, $target_id, null, ($user_table === 'users' ? 'User' : 'Admin') . " account #{$target_id} unblocked");
                    $success = 'Account unblocked.';
                }
            } elseif ($action === 'activate') {
                if ($user_table !== 'admin_users') {
                    $error = 'Only admin accounts can be activated here.';
                } else {
                    $res = activate_admin_account($pdo, $target_id, $_SESSION['admin_role'] ?? '', $_SESSION['admin_id'], $_SESSION['admin_full_name'] ?? '');
                    if (!$res['success']) {
                        $error = $res['message'];
                    } else {
                        $target_name = $res['target']['full_name'] ?: $res['target']['username'];
                        $role_label = ($res['target']['role'] === 'super_admin') ? 'super admin' : 'admin';
                        log_login($pdo, 'admin_users', $_SESSION['admin_id'], $_SESSION['admin_username'] ?? '', $_SESSION['admin_full_name'] ?? '', $_SESSION['admin_role'] ?? '', 'logout', 'success', $_SESSION['admin_id_number'] ?? null);
                        log_audit($pdo, 'logout', 'admin_users', $_SESSION['admin_id'], $_SESSION['admin_full_name'] ?? '', 'Logged out automatically after activating "' . $target_name . '"');
                        $msg = '"' . $target_name . '" has been activated and is now the only active ' . $role_label . ' account. Your account is marked inactive and you have been logged out. Only one active ' . $role_label . ' is allowed at a time.';
                        session_unset(); session_destroy(); session_start();
                        flash_message('success', $msg);
                        redirect('login.php');
                    }
                }
            } else {
                $error = 'Invalid action.';
            }
        } catch (PDOException $e) {
            error_log('[account_management] ' . $e->getMessage());
            $error = 'An error occurred.';
        }
    }
}

auto_inactivate_accounts($pdo);

$tab = ($_GET['tab'] ?? 'users') === 'admins' ? 'admins' : 'users';
$search = trim($_GET['search'] ?? '');
$role_filter = $_GET['role'] ?? '';
$status_filter = $_GET['status'] ?? '';
$page = max(1, intval($_GET['page'] ?? 1));
$per_page = RECORDS_PER_PAGE;

$is_superadmin = (($_SESSION['admin_role'] ?? '') === 'super_admin');
if (!$is_superadmin && $tab === 'admins') {
    // Admin role may view admin accounts only - super admin accounts are hidden
    $role_filter = 'admin';
}
$can_view_admins = $is_superadmin || check_permission($pdo, 'admin_users', $_SESSION['admin_id'], 'admins.view');
$can_block_admins = $is_superadmin || check_permission($pdo, 'admin_users', $_SESSION['admin_id'], 'admins.block');
$can_unblock_admins = $is_superadmin || check_permission($pdo, 'admin_users', $_SESSION['admin_id'], 'admins.unblock');
$can_delete_admins = $is_superadmin || check_permission($pdo, 'admin_users', $_SESSION['admin_id'], 'admins.delete');
$can_update_admins = $is_superadmin || check_permission($pdo, 'admin_users', $_SESSION['admin_id'], 'admins.update');

if ($tab === 'admins' && !$can_view_admins) {
    $tab = 'users';
}

// Role filter is scoped to the active tab's table so it never leaks across tabs.
// Non-super admins are always restricted to admin-role rows on the admins list.
$users_role_filter = ($tab === 'users') ? $role_filter : '';
$admins_role_filter = $is_superadmin ? (($tab === 'admins') ? $role_filter : '') : 'admin';

$result = get_all_users_paginated($pdo, ['search' => $search, 'role' => $users_role_filter, 'status' => $status_filter], $per_page, $page);
$users_data = $result['users'];
$total_users = $result['total'];

$admins_data = [];
$total_admins = 0;
$admins_pagination = [];
if ($can_view_admins) {
    $result = get_all_admins_paginated($pdo, ['search' => $search, 'role' => $admins_role_filter, 'status' => $status_filter], $per_page, $page);
    $admins_data = $result['admins'];
    $total_admins = $result['total'];
    $admins_pagination = $result['pagination'];
}

if ($tab === 'admins') {
    $total = $total_admins;
    $pagination = $admins_pagination;
} else {
    $total = $total_users;
    $pagination = $result['pagination'];
}

generate_csrf_token();
$base = $is_superadmin ? '../superadmin/' : '';
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
    <style>
        .row-actions { width: auto; min-width: 150px; max-width: 200px; font-size: 0.8125rem; }
    </style>
</head>
<body>
    <div class="page-wrapper">
        <aside class="sidebar" id="sidebar">
            <div class="sidebar-header"><a href="<?php echo $base; ?>dashboard.php" class="sidebar-logo"><i class="fas fa-film"></i><span>MovieHub</span></a></div>
            <nav class="sidebar-nav">
<?php require __DIR__ . '/../includes/sidebar_navigation.php'; ?>
</nav>
            <a href="../superadmin/edit_admin.php?id=<?php echo (int)$_SESSION['admin_id']; ?>" class="sidebar-user" style="display:flex;align-items:center;gap:0.75rem;padding:0.75rem 1rem;color:inherit;text-decoration:none;transition:background 0.15s;cursor:pointer;" title="Edit my profile">
                <div class="avatar avatar-sm" style="background:var(--primary);color:white;"><?php echo strtoupper(substr($_SESSION['admin_full_name'], 0, 1)); ?></div>
                <div class="sidebar-user-info">
                    <div class="sidebar-user-name"><?php echo htmlspecialchars($_SESSION['admin_full_name']); ?></div>
                    <div class="sidebar-user-role" style="color:var(--primary);font-weight:600;"><?php echo $is_superadmin ? 'Super Admin' : ucfirst(str_replace('_', ' ', $_SESSION['admin_role'] ?? 'admin')); ?></div>
                </div>
            </a>
        </aside>

        <div class="main-content">
            <div class="top-header">
                <div class="flex items-center gap-3">
                    <button class="sidebar-toggle" onclick="document.getElementById('sidebar').classList.toggle('open');document.getElementById('sidebarOverlay').classList.toggle('active');"><i class="fas fa-bars"></i></button>
                    <div><h1 class="page-title">Account Management</h1><p class="page-subtitle">Manage user and admin accounts (<?php echo number_format($total); ?> records)</p></div>
                </div>
            </div>

            <div class="content-body">
                <?php if ($success): ?><div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($success); ?></div><?php endif; ?>
                <?php if ($error): ?><div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div><?php endif; ?>

                <div class="flex gap-3" style="margin-bottom:1rem;">
                    <a href="?tab=users" class="btn <?php echo $tab==='users'?'btn-primary':'btn-outline'; ?>">Users (<?php echo number_format($total_users); ?>)</a>
                    <?php if ($can_view_admins): ?>
                    <a href="?tab=admins" class="btn <?php echo $tab==='admins'?'btn-primary':'btn-outline'; ?>">Admins (<?php echo number_format($total_admins); ?>)</a>
                    <?php endif; ?>
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
                                <?php if ($is_superadmin): ?>
                                <option value="super_admin" <?php echo $role_filter==='super_admin'?'selected':''; ?>>Super Admin</option>
                                <?php endif; ?>
                                <?php endif; ?>
                            </select></div>
                            <div class="form-group" style="flex:0 0 120px;margin-bottom:0;"><select name="status" class="form-control"><option value="">All Status</option>
                                <option value="active" <?php echo $status_filter==='active'?'selected':''; ?>>Active</option>
                                <option value="inactive" <?php echo $status_filter==='inactive'?'selected':''; ?>>Inactive</option>
                                <option value="approved" <?php echo $status_filter==='approved'?'selected':''; ?>>Approved</option>
                                <option value="online" <?php echo $status_filter==='online'?'selected':''; ?>>Online</option>
                                <option value="offline" <?php echo $status_filter==='offline'?'selected':''; ?>>Offline</option>
                                <option value="pending" <?php echo $status_filter==='pending'?'selected':''; ?>>Pending</option>
                                <option value="blocked" <?php echo $status_filter==='blocked'?'selected':''; ?>>Blocked</option>
                                <option value="rejected" <?php echo $status_filter==='rejected'?'selected':''; ?>>Rejected</option>
                            </select></div>
                            <button type="submit" class="btn btn-primary btn-sm"><i class="fas fa-search"></i></button>
                            <a href="account_management.php?tab=<?php echo htmlspecialchars($tab); ?>" class="btn btn-outline btn-sm"><i class="fas fa-times"></i></a>
                        </form>
                    </div>
                </div>

                <div class="card">
                    <div class="table-responsive">
<?php if ($tab === 'admins'): ?>
                        <table class="table">
                            <thead><tr>
                                <th>ID</th><th>Name</th><th>Username</th><th>Email</th><th>Role</th><th>Status</th><th>Last Login</th><th>Actions</th>
                            </tr></thead>
                            <tbody>
<?php foreach ($admins_data as $a): ?>
                                <tr>
                                    <td><small><?php echo htmlspecialchars($a['id_number'] ?? $a['id']); ?></small></td>
                                    <td><strong><?php echo htmlspecialchars($a['full_name']); ?></strong></td>
                                    <td><?php echo htmlspecialchars($a['username']); ?></td>
                                    <td><small><?php echo htmlspecialchars($a['email']); ?></small></td>
                                    <td><?php echo render_role_badge($a['role']); ?></td>
                                    <td><?php echo render_status_badge($a['account_status']); ?></td>
                                    <td><small><?php echo $a['last_login'] ? date('M d, Y', strtotime($a['last_login'])) : 'Never'; ?></small></td>
                                    <td>
                                        <div class="table-actions">
                                            <?php
                                            $row_can_edit = $is_superadmin || (int)$a['id'] === (int)$_SESSION['admin_id'] || ($can_update_admins && ($a['role'] ?? '') !== 'super_admin');
                                            $row_can_activate = (($a['role'] ?? '') === ($_SESSION['admin_role'] ?? '')) && $a['account_status'] === 'inactive';
                                            $row_can_block = ($a['role'] ?? '') !== 'super_admin' && $can_block_admins && $a['account_status'] !== 'blocked';
                                            $row_can_unblock = ($a['role'] ?? '') !== 'super_admin' && $can_unblock_admins && $a['account_status'] === 'blocked';
                                            $row_can_delete = ($a['role'] ?? '') !== 'super_admin' && (int)$a['id'] !== (int)$_SESSION['admin_id'] && $can_delete_admins;
                                            $row_has_actions = $row_can_edit || $row_can_activate || $row_can_block || $row_can_unblock || $row_can_delete;
                                            ?>
                                            <?php if ($row_has_actions): ?>
                                            <select class="form-control row-actions" onchange="rowAction(this)" aria-label="Actions"<?php if ($row_can_edit) echo ' data-edit="../superadmin/edit_admin.php?id=' . (int)$a['id'] . '"'; ?><?php if ($row_can_delete) echo ' data-delete="delete_user_request.php?table=admin_users&id=' . (int)$a['id'] . '" data-delete-confirm="Send a deletion request to Super Admin for this admin account?"'; ?>>
                                                <option value="">Select action</option>
                                                <?php if ($row_can_edit): ?><option value="edit">Edit</option><?php endif; ?>
                                                <?php if ($row_can_activate): ?><option value="activate">Activate</option><?php endif; ?>
                                                <?php if ($row_can_block): ?><option value="block"><?php echo $is_superadmin ? 'Block' : 'Request Block'; ?></option><?php endif; ?>
                                                <?php if ($row_can_unblock): ?><option value="unblock">Unblock</option><?php endif; ?>
                                                <?php if ($row_can_delete): ?><option value="delete">Request Deletion</option><?php endif; ?>
                                            </select>
                                            <?php else: ?>
                                            <span class="text-muted">&mdash;</span>
                                            <?php endif; ?>
                                            <?php if ($row_can_activate): ?>
                                                <form method="POST" action="" style="display:none;" class="activate-form" data-action="activate" data-name="<?php echo htmlspecialchars($a['full_name']); ?>">
                                                    <?php csrf_token_input(); ?>
                                                    <input type="hidden" name="action" value="activate">
                                                    <input type="hidden" name="user_table" value="admin_users">
                                                    <input type="hidden" name="target_id" value="<?php echo $a['id']; ?>">
                                                </form>
                                            <?php endif; ?>
                                            <?php if ($row_can_block): ?>
                                                <form method="POST" action="" style="display:none;" enctype="multipart/form-data" class="block-form" data-name="<?php echo htmlspecialchars($a['full_name']); ?>" data-action="block" data-type="<?php echo $is_superadmin ? '' : 'request'; ?>">
                                                    <?php csrf_token_input(); ?>
                                                    <input type="hidden" name="action" value="block">
                                                    <input type="hidden" name="user_table" value="admin_users">
                                                    <input type="hidden" name="target_id" value="<?php echo $a['id']; ?>">
                                                </form>
                                            <?php elseif ($row_can_unblock): ?>
                                                <form method="POST" action="" style="display:none;" class="block-form" data-name="<?php echo htmlspecialchars($a['full_name']); ?>" data-action="unblock">
                                                    <?php csrf_token_input(); ?>
                                                    <input type="hidden" name="action" value="unblock">
                                                    <input type="hidden" name="user_table" value="admin_users">
                                                    <input type="hidden" name="target_id" value="<?php echo $a['id']; ?>">
                                                </form>
                                            <?php endif; ?>
                                        </div>
                                    </td>
                                </tr>
<?php endforeach; ?>
<?php if (empty($admins_data)): ?>
                                <tr><td colspan="8" class="text-center text-muted" style="padding:2rem;">No admins found.</td></tr>
<?php endif; ?>
                            </tbody>
                        </table>
<?php else: ?>
                        <table class="table">
                            <thead><tr>
                                <th>ID</th><th>Name</th><th>Username</th><th>Email</th><th>Role</th><th>Status</th><th>Actions</th>
                            </tr></thead>
                            <tbody>
<?php foreach ($users_data as $u): ?>
                                <tr>
                                    <td><small><?php echo htmlspecialchars($u['id_number'] ?? $u['id']); ?></small></td>
                                    <td><strong><?php echo htmlspecialchars($u['first_name'].' '.$u['last_name']); ?></strong></td>
                                    <td><?php echo htmlspecialchars($u['username']); ?></td>
                                    <td><small><?php echo htmlspecialchars($u['email']); ?></small></td>
                                    <td><?php echo render_role_badge($u['role'] ?? 'user'); ?></td>
                                    <td><?php echo render_status_badge($u['account_status']); ?></td>
                                    <td>
                                        <div class="table-actions">
                                            <select class="form-control row-actions" onchange="rowAction(this)" aria-label="Actions" data-edit="edit_user.php?id=<?php echo (int)$u['id']; ?>" data-delete="delete_user_request.php?table=users&id=<?php echo (int)$u['id']; ?>" data-delete-confirm="Send a deletion request to Super Admin for this user?">
                                                <option value="">Select action</option>
                                                <option value="edit">Edit</option>
                                                <?php if ($u['account_status'] !== 'blocked'): ?>
                                                <option value="block"><?php echo $is_superadmin ? 'Block' : 'Request Block'; ?></option>
                                                <?php else: ?>
                                                <option value="unblock">Unblock</option>
                                                <?php endif; ?>
                                                <option value="delete">Request Deletion</option>
                                            </select>
                                            <?php if ($u['account_status'] !== 'blocked'): ?>
                                                <form method="POST" action="" style="display:none;" enctype="multipart/form-data" class="block-form" data-name="<?php echo htmlspecialchars($u['first_name'].' '.$u['last_name']); ?>" data-action="block" data-type="<?php echo $is_superadmin ? '' : 'request'; ?>">
                                                    <?php csrf_token_input(); ?>
                                                    <input type="hidden" name="action" value="block">
                                                    <input type="hidden" name="target_id" value="<?php echo $u['id']; ?>">
                                                </form>
                                            <?php else: ?>
                                                <form method="POST" action="" style="display:none;" class="block-form" data-name="<?php echo htmlspecialchars($u['first_name'].' '.$u['last_name']); ?>" data-action="unblock">
                                                    <?php csrf_token_input(); ?>
                                                    <input type="hidden" name="action" value="unblock">
                                                    <input type="hidden" name="target_id" value="<?php echo $u['id']; ?>">
                                                </form>
                                            <?php endif; ?>
                                        </div>
                                    </td>
                                </tr>
<?php endforeach; ?>
<?php if (empty($users_data)): ?>
                                <tr><td colspan="7" class="text-center text-muted" style="padding:2rem;">No users found.</td></tr>
<?php endif; ?>
                            </tbody>
                        </table>
<?php endif; ?>
                    </div>
                </div>

                <?php if ($pagination['total_pages'] > 1): ?>
                <div class="pagination" style="justify-content:center;margin-top:1.5rem;">
                    <?php
                    $bp = $_GET;
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

    <div id="blockModal" class="modal" style="display:none;">
        <div class="modal-content" style="max-width:440px;">
            <div class="modal-header">
                <h3 class="modal-title" id="blockModalTitle"><i class="fas fa-ban" style="color:var(--danger);"></i> Block Account</h3>
                <button type="button" class="modal-close" onclick="closeBlockModal()" style="background:none;border:none;font-size:1.25rem;color:var(--muted);cursor:pointer;">&times;</button>
            </div>
            <div class="modal-body">
                <div class="alert alert-warning" style="font-size:0.8125rem;">
                    <i class="fas fa-exclamation-triangle"></i> You are about to <strong id="blockActionLabel">block</strong> <strong id="blockTargetName"></strong>.
                </div>
                <div id="blockRequestNote" class="alert alert-info" style="display:none;font-size:0.8125rem;">
                    <i class="fas fa-paper-plane"></i> This will be sent as a <strong>block request</strong> to the Super Admin for approval. The account will not be blocked until approved.
                </div>
                <div class="form-group" id="blockReasonGroup" style="display:none;">
                    <label for="blockReason">Reason for Blocking *</label>
                    <textarea id="blockReason" class="form-control" rows="3" placeholder="Explain why this account should be blocked..."></textarea>
                </div>
                <div class="form-group" id="blockDocGroup" style="display:none;">
                    <label for="blockDocument">Supporting Document *</label>
                    <input type="file" id="blockDocument" class="form-control" accept=".pdf,.jpg,.jpeg,.png,.webp">
                    <small style="font-size:0.6875rem;color:var(--muted);">Attach the document justifying the block (PDF, JPG, PNG, WEBP; max 5MB).</small>
                </div>
                <div class="form-group">
                    <label for="blockPassword">Your Password (to confirm) *</label>
                    <input type="password" id="blockPassword" class="form-control" autocomplete="off" placeholder="Enter YOUR current password to confirm">
                </div>
                <div id="blockValidation" class="alert alert-danger" style="display:none;font-size:0.8125rem;"></div>
            </div>
            <div class="modal-footer" style="display:flex;gap:0.5rem;padding:1rem 1.5rem;border-top:1px solid var(--border);">
                <button type="button" class="btn btn-outline" style="flex:1;" onclick="closeBlockModal()">Cancel</button>
                <button type="button" class="btn btn-danger" style="flex:1;" id="blockConfirmBtn" onclick="confirmBlock()"><i class="fas fa-ban"></i> Confirm</button>
            </div>
        </div>
    </div>

    <div id="activateModal" class="modal" style="display:none;">
        <div class="modal-content" style="max-width:440px;">
            <div class="modal-header">
                <h3 class="modal-title"><i class="fas fa-user-check" style="color:var(--success);"></i> Activate Admin Account</h3>
                <button type="button" class="modal-close" onclick="closeActivateModal()" style="background:none;border:none;font-size:1.25rem;color:var(--muted);cursor:pointer;">&times;</button>
            </div>
            <div class="modal-body">
                <div class="alert alert-warning" style="font-size:0.8125rem;">
                    <i class="fas fa-exclamation-triangle"></i> You are about to activate <strong id="activateTargetName"></strong>.
                    You can only activate accounts of your own role.
                    Only <strong>one active account per role is allowed</strong>:
                    after confirming, <strong>every other active account of the same role
                    (including yours) is marked inactive</strong> and you will be <strong>logged out
                    immediately</strong>. The activated account can then log in.
                </div>
                <div class="form-group">
                    <label for="activatePassword">Your Password (to confirm) *</label>
                    <input type="password" id="activatePassword" class="form-control" autocomplete="off" placeholder="Enter YOUR current password to confirm">
                </div>
                <div id="activateValidation" class="alert alert-danger" style="display:none;font-size:0.8125rem;"></div>
            </div>
            <div class="modal-footer" style="display:flex;gap:0.5rem;padding:1rem 1.5rem;border-top:1px solid var(--border);">
                <button type="button" class="btn btn-outline" style="flex:1;" onclick="closeActivateModal()">Cancel</button>
                <button type="button" class="btn btn-success" style="flex:1;" id="activateConfirmBtn" onclick="confirmActivate()"><i class="fas fa-user-check"></i> Confirm &amp; Activate</button>
            </div>
        </div>
    </div>

    <div id="sidebarOverlay" class="sidebar-overlay" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('active');"></div>

    <script>
        var activeBlockForm = null;
        function openBlockModal(btn) {
            activeBlockForm = btn.closest('form');
            var isBlock = activeBlockForm.getAttribute('data-action') === 'block';
            var isRequest = activeBlockForm.getAttribute('data-type') === 'request';
            document.getElementById('blockTargetName').textContent = activeBlockForm.getAttribute('data-name');
            document.getElementById('blockActionLabel').textContent = isRequest ? 'request to block' : (isBlock ? 'block' : 'unblock');
            document.getElementById('blockModalTitle').innerHTML = '<i class="fas fa-' + (isBlock ? 'ban' : 'unlock') + '" style="color:' + (isBlock ? 'var(--danger)' : 'var(--success)') + ';"></i> ' + (isRequest ? 'Request Block' : (isBlock ? 'Block' : 'Unblock')) + ' Account';
            document.getElementById('blockConfirmBtn').className = isBlock ? 'btn btn-danger' : 'btn btn-success';
            document.getElementById('blockConfirmBtn').innerHTML = '<i class="fas fa-' + (isBlock ? 'ban' : 'unlock') + '"></i> Confirm';
            document.getElementById('blockReasonGroup').style.display = isRequest ? 'block' : 'none';
            document.getElementById('blockDocGroup').style.display = isRequest ? 'block' : 'none';
            document.getElementById('blockRequestNote').style.display = isRequest ? 'block' : 'none';
            document.getElementById('blockReason').value = '';
            document.getElementById('blockDocument').value = '';
            document.getElementById('blockPassword').value = '';
            document.getElementById('blockValidation').style.display = 'none';
            document.getElementById('blockModal').style.display = 'flex';
            document.getElementById('blockPassword').focus();
        }
        function closeBlockModal() { document.getElementById('blockModal').style.display = 'none'; activeBlockForm = null; }

        var activeActivateForm = null;
        function openActivateModal(btn) {
            activeActivateForm = btn.closest('form');
            document.getElementById('activateTargetName').textContent = activeActivateForm.getAttribute('data-name');
            document.getElementById('activatePassword').value = '';
            document.getElementById('activateValidation').style.display = 'none';
            document.getElementById('activateModal').style.display = 'flex';
            document.getElementById('activatePassword').focus();
        }
        function closeActivateModal() { document.getElementById('activateModal').style.display = 'none'; activeActivateForm = null; }
        function confirmActivate() {
            if (!activeActivateForm) return;
            var form = activeActivateForm;
            var password = document.getElementById('activatePassword').value;
            var val = document.getElementById('activateValidation');
            if (!password) { val.textContent = 'You must enter your current password to confirm.'; val.style.display = 'block'; return; }
            val.style.display = 'none';
            if (!confirm('Activate ' + form.getAttribute('data-name') + '? You will be logged out and your account will become inactive.')) return;
            var pwdInput = document.createElement('input');
            pwdInput.type = 'hidden'; pwdInput.name = 'admin_password'; pwdInput.value = password;
            form.appendChild(pwdInput);
            closeActivateModal();
            form.submit();
        }
        function confirmBlock() {
            if (!activeBlockForm) return;
            var form = activeBlockForm;
            var isRequest = form.getAttribute('data-type') === 'request';
            var reason = document.getElementById('blockReason').value.trim();
            var file = document.getElementById('blockDocument').files[0];
            var password = document.getElementById('blockPassword').value;
            var val = document.getElementById('blockValidation');
            if (isRequest && !reason) { val.textContent = 'A reason is required for the block request.'; val.style.display = 'block'; return; }
            if (isRequest && !file) { val.textContent = 'A supporting document is required for the block request.'; val.style.display = 'block'; return; }
            if (isRequest && !/\.(pdf|jpg|jpeg|png|webp)$/i.test(file.name)) { val.textContent = 'Invalid document type. Allowed: PDF, JPG, PNG, WEBP.'; val.style.display = 'block'; return; }
            if (isRequest && file.size > 5*1024*1024) { val.textContent = 'Document must not exceed 5MB.'; val.style.display = 'block'; return; }
            if (!password) { val.textContent = 'You must enter your current password to confirm.'; val.style.display = 'block'; return; }
            val.style.display = 'none';
            var pwdInput = document.createElement('input');
            pwdInput.type = 'hidden'; pwdInput.name = 'admin_password'; pwdInput.value = password;
            form.appendChild(pwdInput);
            if (isRequest) {
                var reasonInput = document.createElement('textarea');
                reasonInput.name = 'reason'; reasonInput.value = reason; reasonInput.style.display = 'none';
                form.appendChild(reasonInput);
                var fileInput = document.createElement('input');
                fileInput.type = 'file'; fileInput.name = 'block_document';
                var dt = new DataTransfer(); dt.items.add(file); fileInput.files = dt.files; fileInput.style.display = 'none';
                form.appendChild(fileInput);
            }
            closeBlockModal();
            form.submit();
        }
        function rowAction(sel) {
            var v = sel.value;
            if (!v) return;
            sel.value = '';
            var cell = sel.closest('.table-actions');
            if (!cell) return;
            if (v === 'edit') {
                var href = sel.getAttribute('data-edit');
                if (href) window.location.href = href;
                return;
            }
            if (v === 'delete') {
                var dhref = sel.getAttribute('data-delete');
                if (dhref) {
                    var cfm = sel.getAttribute('data-delete-confirm');
                    if (!cfm || confirm(cfm)) window.location.href = dhref;
                }
                return;
            }
            if (v === 'block' || v === 'unblock') {
                var bf = cell.querySelector('form[data-action="' + v + '"]');
                if (bf) openBlockModal(bf);
                return;
            }
            if (v === 'activate') {
                var af = cell.querySelector('form[data-action="activate"]');
                if (af) openActivateModal(af);
            }
        }
    </script>
</body>
</html>
