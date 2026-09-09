<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/authorization.php';
require_once '../includes/csrf.php';

require_login();
require_role(['admin', 'super_admin']);
require_permission('logs.view');

$page = max(1, intval($_GET['page'] ?? 1));
$per_page = RECORDS_PER_PAGE;
$search = trim($_GET['search'] ?? '');
$table_filter = $_GET['table_filter'] ?? '';
$action_filter = $_GET['action_filter'] ?? '';
$date_from = $_GET['date_from'] ?? '';
$date_to = $_GET['date_to'] ?? '';

$where = [];
$params = [];

if (($_SESSION['admin_role'] ?? '') !== 'super_admin') {
    $where[] = "ll.role != ?";
    $params[] = 'super_admin';
}

if ($search) {
    $where[] = "(ll.username LIKE ? OR ll.full_name LIKE ? OR ll.ip_address LIKE ?)";
    $s = "%$search%"; $params = array_merge($params, [$s, $s, $s]);
}
if ($table_filter) { $where[] = "ll.user_table = ?"; $params[] = $table_filter; }
if ($action_filter) { $where[] = "ll.action = ?"; $params[] = $action_filter; }
if ($date_from) { $where[] = "ll.created_at >= ?"; $params[] = $date_from . ' 00:00:00'; }
if ($date_to) { $where[] = "ll.created_at <= ?"; $params[] = $date_to . ' 23:59:59'; }

$where_sql = !empty($where) ? 'WHERE ' . implode(' AND ', $where) : '';

$total = 0;
try {
    $count_stmt = $pdo->prepare("SELECT COUNT(*) FROM login_logs ll $where_sql");
    $count_stmt->execute($params);
    $total = $count_stmt->fetchColumn();
} catch (PDOException $e) { error_log('[login_logs] count error: ' . $e->getMessage()); }

$pagination = paginate($total, $page, $per_page);
$logs = [];

try {
    $stmt = $pdo->prepare("SELECT ll.* FROM login_logs ll $where_sql ORDER BY ll.created_at DESC LIMIT {$pagination['per_page']} OFFSET {$pagination['offset']}");
    $stmt->execute($params);
    $logs = $stmt->fetchAll();
} catch (PDOException $e) { error_log('[login_logs] query error: ' . $e->getMessage()); }

generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Logs - MovieHub</title>
    <link rel="stylesheet" href="../assets/css/style.css?v=2.3.0">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body>
    <div class="page-wrapper">
        <aside class="sidebar" id="sidebar">
            <div class="sidebar-header"><a href="<?php echo ($_SESSION['admin_role'] ?? '') === 'super_admin' ? '../superadmin/dashboard.php' : 'dashboard.php'; ?>" class="sidebar-logo"><i class="fas fa-film"></i><span>MovieHub</span></a></div>
            <nav class="sidebar-nav">
<?php if (($_SESSION['admin_role'] ?? '') === 'super_admin'): ?>
                <div class="sidebar-section"><div class="sidebar-section-title">Overview</div>
                    <a href="../superadmin/dashboard.php" class="sidebar-link"><i class="fas fa-tachometer-alt"></i><span>Dashboard</span></a>
                </div>
                <div class="sidebar-section"><div class="sidebar-section-title">User Management</div>
                    <a href="../superadmin/account_management.php" class="sidebar-link"><i class="fas fa-users-cog"></i><span>Account Management</span></a>
                    <a href="../superadmin/create_account.php" class="sidebar-link"><i class="fas fa-user-plus"></i><span>Create Account</span></a>
                    <a href="registration_approval.php" class="sidebar-link"><i class="fas fa-user-check"></i><span>Registration Approvals</span></a>
                    <a href="../superadmin/privilege_management.php" class="sidebar-link"><i class="fas fa-shield-alt"></i><span>Privileges</span></a>
                    <a href="../superadmin/deletion_requests.php" class="sidebar-link"><i class="fas fa-user-minus"></i><span>Deletion Requests</span></a>
                </div>
                <div class="sidebar-section"><div class="sidebar-section-title">Activity</div>
                    <a href="login_logs.php" class="sidebar-link active"><i class="fas fa-history"></i><span>Login Logs</span></a>
                </div>
<?php else: ?>
                <div class="sidebar-section"><div class="sidebar-section-title">Main</div>
                    <a href="dashboard.php" class="sidebar-link"><i class="fas fa-tachometer-alt"></i><span>Dashboard</span></a>
                </div>
                <div class="sidebar-section"><div class="sidebar-section-title">Management</div>
                    <a href="account_management.php" class="sidebar-link"><i class="fas fa-users-cog"></i><span>Account Management</span></a>
                    <a href="manage_movies.php" class="sidebar-link"><i class="fas fa-film"></i><span>Manage Movies</span></a>
                    <a href="manage_genres.php" class="sidebar-link"><i class="fas fa-tags"></i><span>Manage Genres</span></a>
                    <a href="rental_requests.php" class="sidebar-link"><i class="fas fa-clipboard-list"></i><span>Rental Requests</span></a>
                    <a href="registration_approval.php" class="sidebar-link"><i class="fas fa-user-check"></i><span>Approvals</span></a>
                    <a href="login_logs.php" class="sidebar-link active"><i class="fas fa-history"></i><span>Login Logs</span></a>
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
                    <div class="sidebar-user-role" style="color:var(--primary);font-weight:600;"><?php echo ($_SESSION['admin_role'] ?? '') === 'super_admin' ? 'Super Admin' : ucfirst(str_replace('_', ' ', $_SESSION['admin_role'] ?? 'admin')); ?></div>
                </div>
            </a>
        </aside>

        <div class="main-content">
            <div class="top-header">
                <div class="flex items-center gap-3">
                    <button class="sidebar-toggle" onclick="document.getElementById('sidebar').classList.toggle('open');document.getElementById('sidebarOverlay').classList.toggle('active');"><i class="fas fa-bars"></i></button>
                    <div><h1 class="page-title">Login Logs</h1><p class="page-subtitle">Track all login and logout activity (<?php echo number_format($total); ?> records)</p></div>
                </div>
            </div>

            <div class="content-body">
                <div class="card" style="margin-bottom:1.5rem;">
                    <div class="card-body" style="padding:1rem 1.5rem;">
                        <form method="GET" action="" class="flex items-center gap-3" style="flex-wrap:wrap;">
                            <div class="form-group" style="flex:1;min-width:180px;margin-bottom:0;">
                                <input type="text" name="search" class="form-control" placeholder="Search username, name, IP..." value="<?php echo htmlspecialchars($search); ?>">
                            </div>
                            <div class="form-group" style="flex:0 0 130px;margin-bottom:0;">
                                <select name="table_filter" class="form-control">
                                    <option value="">All Users</option>
                                    <option value="users" <?php echo $table_filter==='users'?'selected':''; ?>>Clients</option>
                                    <option value="admin_users" <?php echo $table_filter==='admin_users'?'selected':''; ?>>Admins</option>
                                </select>
                            </div>
                            <div class="form-group" style="flex:0 0 130px;margin-bottom:0;">
                                <select name="action_filter" class="form-control">
                                    <option value="">All Actions</option>
                                    <option value="login" <?php echo $action_filter==='login'?'selected':''; ?>>Login</option>
                                    <option value="logout" <?php echo $action_filter==='logout'?'selected':''; ?>>Logout</option>
                                </select>
                            </div>
                            <div class="form-group" style="flex:0 0 140px;margin-bottom:0;">
                                <input type="date" name="date_from" class="form-control" value="<?php echo htmlspecialchars($date_from); ?>" placeholder="From">
                            </div>
                            <div class="form-group" style="flex:0 0 140px;margin-bottom:0;">
                                <input type="date" name="date_to" class="form-control" value="<?php echo htmlspecialchars($date_to); ?>" placeholder="To">
                            </div>
                            <button type="submit" class="btn btn-primary btn-sm"><i class="fas fa-search"></i> Filter</button>
                            <a href="login_logs.php" class="btn btn-outline btn-sm"><i class="fas fa-times"></i> Clear</a>
                        </form>
                    </div>
                </div>

                <div class="card">
                    <div class="table-responsive">
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>#</th>
                                    <th>User</th>
                                    <th>Type</th>
                                    <th>Action</th>
                                    <th>Status</th>
                                    <th>IP Address</th>
                                    <th>User Agent</th>
                                    <th>Date/Time</th>
                                </tr>
                            </thead>
                            <tbody>
<?php foreach ($logs as $i => $log): ?>
                                <tr>
                                    <td><?php echo $pagination['offset'] + $i + 1; ?></td>
                                    <td>
                                        <strong><?php echo htmlspecialchars($log['full_name']); ?></strong><br>
                                        <small class="text-muted"><?php echo htmlspecialchars($log['username']); ?></small>
                                        <?php if (!empty($log['employee_id'])): ?><br><small class="text-muted"><?php echo htmlspecialchars($log['employee_id']); ?></small><?php endif; ?>
                                    </td>
                                    <td><?php echo render_role_badge($log['role']); ?></td>
                                    <td>
                                        <?php if ($log['action'] === 'login'): ?>
                                            <span class="badge badge-info"><i class="fas fa-sign-in-alt"></i> Login</span>
                                        <?php else: ?>
                                            <span class="badge badge-secondary"><i class="fas fa-sign-out-alt"></i> Logout</span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <?php if ($log['status'] === 'success'): ?>
                                            <span class="badge badge-success">Success</span>
                                        <?php else: ?>
                                            <span class="badge badge-danger"><?php echo ucfirst(htmlspecialchars($log['status'])); ?></span>
                                        <?php endif; ?>
                                    </td>
                                    <td><small><?php echo htmlspecialchars($log['ip_address']); ?></small></td>
                                    <td><small class="text-muted" style="max-width:150px;display:inline-block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><?php echo htmlspecialchars(substr($log['user_agent'], 0, 60)); ?><?php echo strlen($log['user_agent']) > 60 ? '...' : ''; ?></small></td>
                                    <td><small><?php echo date('M d, Y H:i:s', strtotime($log['created_at'])); ?></small></td>
                                </tr>
<?php endforeach; ?>
<?php if (empty($logs)): ?>
                                <tr><td colspan="8" class="text-center text-muted" style="padding:2rem;">No login logs found.</td></tr>
<?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>

                <?php if ($pagination['total_pages'] > 1): ?>
                <div class="pagination" style="justify-content:center;margin-top:1.5rem;">
                    <?php
                    $base_params = $_GET;
                    if ($page > 1) {
                        $base_params['page'] = $page - 1;
                        echo '<a href="?' . http_build_query($base_params) . '" class="btn btn-outline btn-sm"><i class="fas fa-chevron-left"></i> Prev</a>';
                    }
                    $start = max(1, $page - 2);
                    $end = min($pagination['total_pages'], $page + 2);
                    for ($i = $start; $i <= $end; $i++) {
                        $base_params['page'] = $i;
                        $active = ($i === $page) ? 'btn-primary' : 'btn-outline';
                        echo '<a href="?' . http_build_query($base_params) . '" class="btn ' . $active . ' btn-sm">' . $i . '</a>';
                    }
                    if ($page < $pagination['total_pages']) {
                        $base_params['page'] = $page + 1;
                        echo '<a href="?' . http_build_query($base_params) . '" class="btn btn-outline btn-sm">Next <i class="fas fa-chevron-right"></i></a>';
                    }
                    ?>
                </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <div id="sidebarOverlay" class="sidebar-overlay" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('active');"></div>
</body>
</html>
