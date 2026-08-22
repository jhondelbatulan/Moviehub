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
                if (empty($reason)) { $error = 'A reason is required to delete an account.'; }
                else {
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

                        $pdo->commit();
                        $success = 'Account for ' . htmlspecialchars($target_name) . ' has been permanently deleted.';
                    } catch (PDOException $ex) {
                        $pdo->rollBack();
                        error_log('[account_management] delete error: ' . $ex->getMessage());
                        $error = 'Failed to delete account.';
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
                    <a href="../admin/registration_approval.php" class="sidebar-link"><i class="fas fa-user-check"></i><span>Registration Approvals</span></a>
                    <a href="privilege_management.php" class="sidebar-link"><i class="fas fa-shield-alt"></i><span>Privileges</span></a>
                    <a href="deletion_requests.php" class="sidebar-link"><i class="fas fa-user-minus"></i><span>Deletion Requests</span></a>
                </div>
                <div class="sidebar-section"><div class="sidebar-section-title">Activity</div>
                    <a href="../admin/login_logs.php" class="sidebar-link"><i class="fas fa-history"></i><span>Login Logs</span></a>
                </div>
                <div class="sidebar-section"><div class="sidebar-section-title">Account</div>
                    <a href="../client/logout.php" class="sidebar-link"><i class="fas fa-sign-out-alt"></i><span>Logout</span></a>
                </div>
            </nav>
            <div class="sidebar-user">
                <div class="avatar avatar-sm" style="background:var(--primary);color:white;"><?php echo strtoupper(substr($_SESSION['admin_full_name'], 0, 1)); ?></div>
                <div class="sidebar-user-info">
                    <div class="sidebar-user-name"><?php echo htmlspecialchars($_SESSION['admin_full_name']); ?></div>
                    <div class="sidebar-user-role" style="color:var(--primary);font-weight:600;">Super Admin</div>
                </div>
            </div>
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
                                            <form method="POST" action="" style="display:inline;" onsubmit="var r=prompt('Enter a reason to delete this user:');if(!r||r.trim()===''){return false;}this.reason.value=r.trim();return confirm('Permanently delete user <?php echo htmlspecialchars(addslashes($u['first_name'].' '.$u['last_name'])); ?>? This cannot be undone.');">
                                                <?php csrf_token_input(); ?>
                                                <input type="hidden" name="action" value="delete_account">
                                                <input type="hidden" name="user_table" value="users">
                                                <input type="hidden" name="target_id" value="<?php echo $u['id']; ?>">
                                                <input type="hidden" name="reason" value="">
                                                <button class="btn btn-sm btn-danger" title="Delete Account"><i class="fas fa-trash"></i></button>
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
                                                <form method="POST" action="" style="display:inline;" onsubmit="var r=prompt('Enter a reason to delete this admin:');if(!r||r.trim()===''){return false;}this.reason.value=r.trim();return confirm('Permanently delete admin <?php echo htmlspecialchars(addslashes($a['full_name'])); ?>? This cannot be undone.');">
                                                    <?php csrf_token_input(); ?>
                                                    <input type="hidden" name="action" value="delete_account">
                                                    <input type="hidden" name="user_table" value="admin_users">
                                                    <input type="hidden" name="target_id" value="<?php echo $a['id']; ?>">
                                                    <input type="hidden" name="reason" value="">
                                                    <button class="btn btn-sm btn-danger" title="Delete Account"><i class="fas fa-trash"></i></button>
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

    <div id="sidebarOverlay" class="sidebar-overlay" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('active');"></div>
</body>
</html>
