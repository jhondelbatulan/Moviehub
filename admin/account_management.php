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

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action'])) {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token.';
    } else {
        $action = $_POST['action'];
        $target_id = intval($_POST['target_id'] ?? 0);
        $user_table = ($_POST['user_table'] ?? 'users') === 'admin_users' ? 'admin_users' : 'users';

        try {
            if ($user_table === 'admin_users') {
                if ($action === 'block' && check_permission($pdo, 'admin_users', $_SESSION['admin_id'], 'admins.block')) {
                    block_account($pdo, 'admin_users', $target_id, 'Blocked by Admin');
                    $success = 'Admin account blocked.';
                } elseif ($action === 'unblock' && check_permission($pdo, 'admin_users', $_SESSION['admin_id'], 'admins.unblock')) {
                    unblock_account($pdo, 'admin_users', $target_id);
                    $success = 'Admin account unblocked.';
                } else {
                    $error = 'You do not have permission for this action.';
                }
            } else {
                if ($action === 'block') {
                    block_account($pdo, 'users', $target_id, 'Blocked by Admin');
                    $success = 'Account blocked.';
                } elseif ($action === 'unblock') {
                    unblock_account($pdo, 'users', $target_id);
                    $success = 'Account unblocked.';
                } else {
                    $error = 'Invalid action.';
                }
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
$can_view_admins = $is_superadmin || check_permission($pdo, 'admin_users', $_SESSION['admin_id'], 'admins.view');
$can_block_admins = $is_superadmin || check_permission($pdo, 'admin_users', $_SESSION['admin_id'], 'admins.block');
$can_unblock_admins = $is_superadmin || check_permission($pdo, 'admin_users', $_SESSION['admin_id'], 'admins.unblock');

if ($tab === 'admins' && !$can_view_admins) {
    $tab = 'users';
}

$result = get_all_users_paginated($pdo, ['search' => $search, 'role' => $role_filter, 'status' => $status_filter], $per_page, $page);
$users_data = $result['users'];
$total_users = $result['total'];

$admins_data = [];
$total_admins = 0;
$admins_pagination = [];
if ($can_view_admins) {
    $result = get_all_admins_paginated($pdo, ['search' => $search, 'role' => $role_filter, 'status' => $status_filter], $per_page, $page);
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
</head>
<body>
    <div class="page-wrapper">
        <aside class="sidebar" id="sidebar">
            <div class="sidebar-header"><a href="<?php echo $base; ?>dashboard.php" class="sidebar-logo"><i class="fas fa-film"></i><span>MovieHub</span></a></div>
            <nav class="sidebar-nav">
<?php if ($is_superadmin): ?>
                <div class="sidebar-section"><div class="sidebar-section-title">Overview</div>
                    <a href="<?php echo $base; ?>dashboard.php" class="sidebar-link"><i class="fas fa-tachometer-alt"></i><span>Dashboard</span></a>
                </div>
                <div class="sidebar-section"><div class="sidebar-section-title">User Management</div>
                    <a href="<?php echo $base; ?>account_management.php" class="sidebar-link active"><i class="fas fa-users-cog"></i><span>Account Management</span></a>
                    <a href="<?php echo $base; ?>create_account.php" class="sidebar-link"><i class="fas fa-user-plus"></i><span>Create Account</span></a>
                    <a href="registration_approval.php" class="sidebar-link"><i class="fas fa-user-check"></i><span>Registration Approvals</span></a>
                    <a href="<?php echo $base; ?>privilege_management.php" class="sidebar-link"><i class="fas fa-shield-alt"></i><span>Privileges</span></a>
                    <a href="<?php echo $base; ?>deletion_requests.php" class="sidebar-link"><i class="fas fa-user-minus"></i><span>Deletion Requests</span></a>
                </div>
                <div class="sidebar-section"><div class="sidebar-section-title">Activity</div>
                    <a href="login_logs.php" class="sidebar-link"><i class="fas fa-history"></i><span>Login Logs</span></a>
                </div>
<?php else: ?>
                <div class="sidebar-section"><div class="sidebar-section-title">Main</div>
                    <a href="dashboard.php" class="sidebar-link"><i class="fas fa-tachometer-alt"></i><span>Dashboard</span></a>
                </div>
                <div class="sidebar-section"><div class="sidebar-section-title">Management</div>
                    <a href="account_management.php" class="sidebar-link active"><i class="fas fa-users-cog"></i><span>Account Management</span></a>
                    <a href="manage_movies.php" class="sidebar-link"><i class="fas fa-film"></i><span>Manage Movies</span></a>
                    <a href="manage_genres.php" class="sidebar-link"><i class="fas fa-tags"></i><span>Manage Genres</span></a>
                    <a href="rental_requests.php" class="sidebar-link"><i class="fas fa-clipboard-list"></i><span>Rental Requests</span></a>
                    <a href="registration_approval.php" class="sidebar-link"><i class="fas fa-user-check"></i><span>Approvals</span></a>
                    <a href="login_logs.php" class="sidebar-link"><i class="fas fa-history"></i><span>Login Logs</span></a>
                </div>
<?php endif; ?>
                <div class="sidebar-section"><div class="sidebar-section-title">Account</div>
                    <a href="../client/logout.php" class="sidebar-link"><i class="fas fa-sign-out-alt"></i><span>Logout</span></a>
                </div>
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
                                    <td><small><?php echo htmlspecialchars($a['employee_id'] ?? $a['id']); ?></small></td>
                                    <td><strong><?php echo htmlspecialchars($a['full_name']); ?></strong></td>
                                    <td><?php echo htmlspecialchars($a['username']); ?></td>
                                    <td><small><?php echo htmlspecialchars($a['email']); ?></small></td>
                                    <td><?php echo render_role_badge($a['role']); ?></td>
                                    <td><?php echo render_status_badge($a['account_status']); ?></td>
                                    <td><small><?php echo $a['last_login'] ? date('M d, Y', strtotime($a['last_login'])) : 'Never'; ?></small></td>
                                    <td>
                                        <div class="table-actions">
                                            <?php if ($is_superadmin || (int)$a['id'] === (int)$_SESSION['admin_id']): ?>
                                                <a href="../superadmin/edit_admin.php?id=<?php echo $a['id']; ?>" class="btn btn-sm btn-outline" title="Edit"><i class="fas fa-edit"></i></a>
                                            <?php endif; ?>
                                            <?php if (($a['role'] ?? '') !== 'super_admin' && $can_block_admins && $a['account_status'] !== 'blocked'): ?>
                                                <form method="POST" action="" style="display:inline;" onsubmit="return confirm('Block this admin?');">
                                                    <?php csrf_token_input(); ?>
                                                    <input type="hidden" name="action" value="block">
                                                    <input type="hidden" name="user_table" value="admin_users">
                                                    <input type="hidden" name="target_id" value="<?php echo $a['id']; ?>">
                                                    <button class="btn btn-sm btn-outline-danger" title="Block"><i class="fas fa-ban"></i></button>
                                                </form>
                                            <?php elseif (($a['role'] ?? '') !== 'super_admin' && $can_unblock_admins && $a['account_status'] === 'blocked'): ?>
                                                <form method="POST" action="" style="display:inline;" onsubmit="return confirm('Unblock this admin?');">
                                                    <?php csrf_token_input(); ?>
                                                    <input type="hidden" name="action" value="unblock">
                                                    <input type="hidden" name="user_table" value="admin_users">
                                                    <input type="hidden" name="target_id" value="<?php echo $a['id']; ?>">
                                                    <button class="btn btn-sm btn-success" title="Unblock"><i class="fas fa-unlock"></i></button>
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
                                                    <input type="hidden" name="target_id" value="<?php echo $u['id']; ?>">
                                                    <button class="btn btn-sm btn-outline-danger" title="Block"><i class="fas fa-ban"></i></button>
                                                </form>
                                            <?php else: ?>
                                                <form method="POST" action="" style="display:inline;" onsubmit="return confirm('Unblock this user?');">
                                                    <?php csrf_token_input(); ?>
                                                    <input type="hidden" name="action" value="unblock">
                                                    <input type="hidden" name="target_id" value="<?php echo $u['id']; ?>">
                                                    <button class="btn btn-sm btn-success" title="Unblock"><i class="fas fa-unlock"></i></button>
                                                </form>
                                            <?php endif; ?>
                                            <a href="delete_user_request.php?table=users&id=<?php echo $u['id']; ?>" class="btn btn-sm btn-outline-danger" title="Request Deletion" onclick="return confirm('Send a deletion request to Super Admin for this user?');"><i class="fas fa-trash"></i></a>
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

    <div id="sidebarOverlay" class="sidebar-overlay" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('active');"></div>
</body>
</html>
