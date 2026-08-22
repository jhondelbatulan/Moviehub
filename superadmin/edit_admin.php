<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/authorization.php';
require_once '../includes/csrf.php';

require_login();
require_role('super_admin');

$admin_id = intval($_GET['id'] ?? 0);
$error = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if ($admin_id <= 0) {
        $error = 'Invalid admin ID.';
    } elseif (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token.';
    } else {
        $full_name = trim($_POST['full_name'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $phone = trim($_POST['phone'] ?? '');
        $address = trim($_POST['address'] ?? '');
        $role = $_POST['role'] ?? '';
        $account_status = $_POST['account_status'] ?? '';

        if ($full_name === '' || $email === '') {
            $error = 'Please fill in all required fields.';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = 'Invalid email address.';
        } elseif (!in_array($role, ['admin', 'super_admin'], true)) {
            $error = 'Invalid role.';
        } elseif (!in_array($account_status, ['active', 'blocked'], true)) {
            $error = 'Invalid account status.';
        } else {
            try {
                $stmt = $pdo->prepare("SELECT id FROM admin_users WHERE email = ? AND id != ?");
                $stmt->execute([$email, $admin_id]);
                if ($stmt->fetch()) {
                    $error = 'That email address is already used by another account.';
                } else {
                    $stmt = $pdo->prepare("UPDATE admin_users SET full_name = ?, email = ?, phone = ?, address = ?, role = ?, account_status = ? WHERE id = ?");
                    $stmt->execute([
                        $full_name,
                        $email,
                        $phone !== '' ? $phone : null,
                        $address !== '' ? $address : null,
                        $role,
                        $account_status,
                        $admin_id
                    ]);
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
                            <div class="form-group"><label>Full Name *</label><input type="text" name="full_name" class="form-control" required maxlength="100" value="<?php echo htmlspecialchars($admin['full_name']); ?>"></div>
                            <div class="form-group"><label>Email *</label><input type="email" name="email" class="form-control" required maxlength="100" value="<?php echo htmlspecialchars($admin['email']); ?>"></div>
                            <div class="form-group"><label>Phone</label><input type="tel" name="phone" class="form-control" maxlength="20" value="<?php echo htmlspecialchars($admin['phone'] ?? ''); ?>"></div>
                            <div class="form-group"><label>Address</label><input type="text" name="address" class="form-control" maxlength="255" value="<?php echo htmlspecialchars($admin['address'] ?? ''); ?>"></div>
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
                                    </select>
                                </div>
                            </div>
                            <p class="text-muted text-sm"><i class="fas fa-lock"></i> Password cannot be changed from this page.</p>
                            <div style="display:flex;gap:0.75rem;">
                                <button type="submit" class="btn btn-primary"><i class="fas fa-save"></i> Save Changes</button>
                                <a href="account_management.php" class="btn btn-outline">Cancel</a>
                            </div>
                        </form>
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
