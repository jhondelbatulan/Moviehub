<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/authorization.php';
require_once '../includes/csrf.php';

require_login();
require_role('super_admin');
require_permission('dashboard.view');

try {
    $total_users = $pdo->query("SELECT COUNT(*) FROM users WHERE is_deleted = 0")->fetchColumn();
    $total_admins = $pdo->query("SELECT COUNT(*) FROM admin_users WHERE is_deleted = 0")->fetchColumn();
    $total_movies = $pdo->query("SELECT COUNT(*) FROM movies")->fetchColumn();
    $pending_requests = $pdo->query("SELECT COUNT(*) FROM rentals WHERE status = 'pending'")->fetchColumn();
    $pending_approvals = $pdo->query("SELECT COUNT(*) FROM registration_approvals WHERE status = 'pending'")->fetchColumn();
    $active_rentals = $pdo->query("SELECT COUNT(*) FROM rentals WHERE status = 'approved'")->fetchColumn();
    $blocked_users = $pdo->query("SELECT COUNT(*) FROM users WHERE account_status = 'blocked' AND is_deleted = 0")->fetchColumn();
    $blocked_admins = $pdo->query("SELECT COUNT(*) FROM admin_users WHERE account_status = 'blocked' AND is_deleted = 0")->fetchColumn();
    $pending_deletions = $pdo->query("SELECT COUNT(*) FROM deletion_requests WHERE status = 'pending'")->fetchColumn();
    $total_revenue = $pdo->query("SELECT COALESCE(SUM(rental_price),0) FROM rentals WHERE status = 'approved'")->fetchColumn();
} catch (PDOException $e) { $total_users=$total_admins=$total_movies=$pending_requests=$pending_approvals=$active_rentals=$blocked_users=$blocked_admins=$pending_deletions=$total_revenue=0; }

try {
    $recent_users = $pdo->query("SELECT id, employee_id, username, CONCAT(first_name,' ',last_name) as full_name, email, role, account_status, created_at FROM users WHERE is_deleted = 0 ORDER BY created_at DESC LIMIT 5")->fetchAll();
} catch (PDOException $e) { $recent_users = []; }

try {
    $recent_logins = $pdo->query("SELECT * FROM login_logs ORDER BY created_at DESC LIMIT 10")->fetchAll();
} catch (PDOException $e) { $recent_logins = []; }

generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Super Admin Dashboard - MovieHub</title>
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
                    <a href="dashboard.php" class="sidebar-link active"><i class="fas fa-tachometer-alt"></i><span>Dashboard</span></a>
                </div>
                <div class="sidebar-section"><div class="sidebar-section-title">User Management</div>
                    <a href="account_management.php" class="sidebar-link"><i class="fas fa-users-cog"></i><span>Account Management</span></a>
                    <a href="create_account.php" class="sidebar-link"><i class="fas fa-user-plus"></i><span>Create Account</span></a>
                    <a href="../admin/registration_approval.php" class="sidebar-link"><i class="fas fa-user-check"></i><span>Registration Approvals</span>
                        <?php if ($pending_approvals > 0): ?><span class="badge badge-warning"><?php echo $pending_approvals; ?></span><?php endif; ?>
                    </a>
                    <a href="privilege_management.php" class="sidebar-link"><i class="fas fa-shield-alt"></i><span>Privileges</span></a>
                    <a href="deletion_requests.php" class="sidebar-link">
                        <i class="fas fa-user-minus"></i><span>Deletion Requests</span>
                        <?php if ($pending_deletions > 0): ?><span class="badge badge-warning"><?php echo $pending_deletions; ?></span><?php endif; ?>
                    </a>
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
                    <div><h1 class="page-title">Super Admin Dashboard</h1><p class="page-subtitle">System overview and management</p></div>
                </div>
                <div class="header-actions"><span class="text-sm text-muted"><i class="fas fa-calendar"></i> <?php echo date('M d, Y'); ?></span></div>
            </div>

            <div class="content-body">
                <?php if ($pending_approvals > 0 || $pending_deletions > 0): ?>
                <div class="alert alert-warning" style="margin-bottom:1.5rem;">
                    <i class="fas fa-bell"></i>
                    <?php if ($pending_approvals > 0): ?><strong><?php echo $pending_approvals; ?></strong> pending registration(s) <a href="../admin/registration_approval.php" class="btn btn-sm btn-warning" style="margin-left:0.25rem;">Review</a> <?php endif; ?>
                    <?php if ($pending_deletions > 0): ?><strong><?php echo $pending_deletions; ?></strong> deletion request(s) <a href="deletion_requests.php" class="btn btn-sm btn-warning" style="margin-left:0.25rem;">Review</a><?php endif; ?>
                </div>
                <?php endif; ?>

                <div class="dashboard-grid">
                    <div class="stat-card"><div class="stat-card-icon green"><i class="fas fa-users"></i></div><div class="stat-card-value"><?php echo $total_users; ?></div><div class="stat-card-label">Total Users</div></div>
                    <div class="stat-card"><div class="stat-card-icon purple"><i class="fas fa-user-shield"></i></div><div class="stat-card-value"><?php echo $total_admins; ?></div><div class="stat-card-label">Admins</div></div>
                    <div class="stat-card"><div class="stat-card-icon teal"><i class="fas fa-film"></i></div><div class="stat-card-value"><?php echo $total_movies; ?></div><div class="stat-card-label">Movies</div></div>
                    <div class="stat-card"><div class="stat-card-icon amber"><i class="fas fa-clock"></i></div><div class="stat-card-value"><?php echo $pending_requests; ?></div><div class="stat-card-label">Pending Requests</div></div>
                    <div class="stat-card"><div class="stat-card-icon blue"><i class="fas fa-check-circle"></i></div><div class="stat-card-value"><?php echo $active_rentals; ?></div><div class="stat-card-label">Active Rentals</div></div>
                    <div class="stat-card"><div class="stat-card-icon red"><i class="fas fa-ban"></i></div><div class="stat-card-value"><?php echo $blocked_users + $blocked_admins; ?></div><div class="stat-card-label">Blocked Accounts</div></div>
                </div>

                <div style="display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;">
                    <div class="card">
                        <div class="card-header">
                            <h3 class="card-title"><i class="fas fa-user-plus"></i> Recent Users</h3>
                            <a href="account_management.php" class="btn btn-sm btn-outline">View All</a>
                        </div>
                        <div class="table-responsive">
                            <table class="table">
                                <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Joined</th></tr></thead>
                                <tbody>
<?php foreach ($recent_users as $u): ?>
                                    <tr>
                                        <td><strong><?php echo htmlspecialchars($u['full_name']); ?></strong><br><small class="text-muted"><?php echo htmlspecialchars($u['employee_id'] ?? $u['username']); ?></small></td>
                                        <td><?php echo render_role_badge($u['role']); ?></td>
                                        <td><?php echo render_status_badge($u['account_status']); ?></td>
                                        <td><small><?php echo date('M d', strtotime($u['created_at'])); ?></small></td>
                                    </tr>
<?php endforeach; ?>
<?php if (empty($recent_users)): ?>
                                    <tr><td colspan="4" class="text-center text-muted" style="padding:1rem;">No users yet.</td></tr>
<?php endif; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <h3 class="card-title"><i class="fas fa-history"></i> Recent Activity</h3>
                            <a href="../admin/login_logs.php" class="btn btn-sm btn-outline">View All</a>
                        </div>
                        <div class="table-responsive">
                            <table class="table">
                                <thead><tr><th>User</th><th>Action</th><th>Result</th><th>Time</th></tr></thead>
                                <tbody>
<?php foreach (array_slice($recent_logins, 0, 8) as $log): ?>
                                    <tr>
                                        <td><strong><?php echo htmlspecialchars($log['full_name']); ?></strong></td>
                                        <td><?php echo ucfirst($log['action']); ?></td>
                                        <td><span class="badge badge-<?php echo $log['status'] === 'success' ? 'success' : 'danger'; ?>"><?php echo ucfirst($log['status']); ?></span></td>
                                        <td><small><?php echo date('M d H:i', strtotime($log['created_at'])); ?></small></td>
                                    </tr>
<?php endforeach; ?>
<?php if (empty($recent_logins)): ?>
                                    <tr><td colspan="4" class="text-center text-muted" style="padding:1rem;">No activity yet.</td></tr>
<?php endif; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div id="sidebarOverlay" class="sidebar-overlay" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('active');"></div>
</body>
</html>
