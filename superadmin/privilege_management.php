<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/authorization.php';
require_once '../includes/csrf.php';

require_login();
require_role('super_admin');
require_permission('privileges.view');

$success = '';
$error = '';

$all_permissions = [];
$all_permission_count = 0;
try {
    $all_perms_raw = $pdo->query("SELECT * FROM permissions ORDER BY category, permission_key")->fetchAll(PDO::FETCH_ASSOC);
    foreach ($all_perms_raw as $perm_row) {
        $category_name = (isset($perm_row['category']) && trim($perm_row['category']) !== '') ? trim($perm_row['category']) : 'Other';
        $all_permissions[$category_name][] = $perm_row;
    }
} catch (PDOException $e) {
    $all_permissions = [];
}
foreach ($all_permissions as $cat_perms) {
    $all_permission_count += count($cat_perms);
}

// Determine allowed privilege keys per role from the actual role_permissions table.
$allowed_by_role = ['super_admin' => [], 'admin' => [], 'user' => []];
try {
    $stmt = $pdo->query(
        "SELECT rp.role, p.permission_key FROM role_permissions rp
         JOIN permissions p ON rp.permission_id = p.id
         WHERE rp.granted = 1"
    );
    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $r = $row['role'];
        if (isset($allowed_by_role[$r])) {
            $allowed_by_role[$r][] = $row['permission_key'];
        }
    }
} catch (PDOException $e) {
    $allowed_by_role = ['super_admin' => [], 'admin' => [], 'user' => []];
}

// Super Admin always has full access to every privilege.
$allowed_by_role['super_admin'] = array_column(array_merge(...array_values($all_permissions)), 'permission_key');

$roles_to_show = [
    'super_admin' => 'Super Admin',
    'admin'       => 'Admin',
    'user'        => 'User',
];

function role_has_privilege($role_key, $perm_key, $allowed_by_role) {
    return in_array($perm_key, $allowed_by_role[$role_key], true);
}

generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Privilege Management - MovieHub</title>
    <link rel="stylesheet" href="../assets/css/style.css?v=2.3.0">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        .role-card-grid { display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:1.25rem; }
        .role-card .card-header { display:flex;align-items:center;justify-content:space-between;gap:0.75rem; }
        .role-count { font-size:0.75rem;font-weight:700;color:var(--text-light);background:rgba(148,163,184,0.12);padding:0.25rem 0.6rem;border-radius:999px;white-space:nowrap; }
        .role-perm-grid { display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:1rem 1.25rem; }
        .role-cat-title { font-size:0.6875rem;font-weight:700;text-transform:uppercase;letter-spacing:0.04em;color:var(--text-light);margin:0 0 0.4rem;padding-bottom:0.3rem;border-bottom:1px solid var(--border); }
        .role-perm { display:flex;align-items:center;gap:0.45rem;padding:0.3rem 0;font-size:0.8125rem;color:var(--text); }
        .role-perm-label { overflow:hidden;text-overflow:ellipsis;white-space:nowrap; }
        .role-allowed { color:var(--success);flex-shrink:0;font-size:0.9rem; }
        .role-denied { color:var(--danger);flex-shrink:0;font-size:0.9rem; }
    </style>

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
                    <a href="account_management.php" class="sidebar-link"><i class="fas fa-users-cog"></i><span>Account Management</span></a>
                    <a href="create_account.php" class="sidebar-link"><i class="fas fa-user-plus"></i><span>Create Account</span></a>
                    <a href="privilege_management.php" class="sidebar-link active"><i class="fas fa-shield-alt"></i><span>Privileges</span></a>
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
                    <div><h1 class="page-title">Privilege Management</h1><p class="page-subtitle">Overview of the privileges allowed for each role</p></div>
                </div>
            </div>

            <div class="content-body">
                <?php if ($success): ?><div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($success); ?></div><?php endif; ?>
                <?php if ($error): ?><div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div><?php endif; ?>

                <p class="text-muted" style="margin-bottom:1.25rem;font-size:0.875rem;">
                    <i class="fas fa-info-circle"></i> A green <i class="fas fa-check-circle" style="color:var(--success);"></i> means the privilege is <strong>allowed</strong> for that role; a red <i class="fas fa-times-circle" style="color:var(--danger);"></i> means it is <strong>not allowed</strong>.
                </p>

                <div class="role-card-grid">
                    <?php foreach ($roles_to_show as $role_key => $role_label): ?>
                        <?php $allowed_count = count($allowed_by_role[$role_key]); ?>
                        <?php $denied_count = $all_permission_count - $allowed_count; ?>
                        <div class="card role-card">
                            <div class="card-header">
                                <h3 class="card-title" style="font-size:1rem;margin:0;">
                                    <i class="fas fa-user-shield" style="color:var(--primary);"></i> <?php echo $role_label; ?>
                                </h3>
                                <span class="role-count"><?php echo $allowed_count; ?>/<?php echo $all_permission_count; ?> allowed</span>
                            </div>
                            <div class="card-body">
                                <?php if ($role_key === 'super_admin'): ?>
                                    <p class="text-muted" style="font-size:0.8125rem;margin:0 0 0.75rem;"><i class="fas fa-crown" style="color:var(--warning);"></i> Full access to all features automatically.</p>
                                <?php endif; ?>
                                <div class="role-perm-grid">
                                    <?php foreach ($all_permissions as $category => $perms): ?>
                                        <div class="role-cat">
                                            <div class="role-cat-title"><?php echo htmlspecialchars(ucfirst($category)); ?></div>
                                            <?php foreach ($perms as $perm): ?>
                                                <?php
                                                $perm_key = $perm['permission_key'];
                                                $perm_desc = (isset($perm['description']) && trim($perm['description']) !== '') ? trim($perm['description']) : $perm_key;
                                                $allowed = role_has_privilege($role_key, $perm_key, $allowed_by_role);
                                                ?>
                                                <div class="role-perm">
                                                    <i class="fas fa-<?php echo $allowed ? 'check-circle' : 'times-circle'; ?> role-<?php echo $allowed ? 'allowed' : 'denied'; ?>"></i>
                                                    <span class="role-perm-label" title="<?php echo htmlspecialchars($perm_key); ?>"><?php echo htmlspecialchars($perm_desc); ?></span>
                                                </div>
                                            <?php endforeach; ?>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>
    </div>

    <div id="sidebarOverlay" class="sidebar-overlay" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('active');"></div>
</body>
</html>
