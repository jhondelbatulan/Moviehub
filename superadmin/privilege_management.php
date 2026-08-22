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

$essential_map = [
    'admin' => ['dashboard.view'],
    'user' => ['dashboard.view', 'movies.view', 'rentals.view', 'logs.view']
];

$essential_fallback_ids = [
    'dashboard.view' => 1,
    'movies.view' => 17,
    'rentals.view' => 21,
    'logs.view' => 27
];

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token.';
    } else {
        $role = $_POST['role'] ?? '';
        $permission_ids = isset($_POST['permissions']) && is_array($_POST['permissions']) ? $_POST['permissions'] : [];

        if (!in_array($role, ['super_admin', 'admin', 'user'])) {
            $error = 'Invalid role.';
        } elseif ($role === 'super_admin') {
            $error = 'Super Admin permissions cannot be restricted.';
        } else {
            try {
                $essential_keys = $essential_map[$role];
                $placeholders = implode(',', array_fill(0, count($essential_keys), '?'));
                $stmt = $pdo->prepare("SELECT id FROM permissions WHERE permission_key IN ($placeholders)");
                $stmt->execute($essential_keys);
                $essential_ids = array_map('intval', $stmt->fetchAll(PDO::FETCH_COLUMN));

                foreach ($essential_keys as $essential_key) {
                    if (isset($essential_fallback_ids[$essential_key]) && !in_array($essential_fallback_ids[$essential_key], $essential_ids)) {
                        $essential_ids[] = $essential_fallback_ids[$essential_key];
                    }
                }

                $permission_ids = array_unique(array_merge(array_map('intval', $permission_ids), $essential_ids));

                $pdo->beginTransaction();
                $stmt = $pdo->prepare("DELETE FROM role_permissions WHERE role = ?");
                $stmt->execute([$role]);

                if (!empty($permission_ids)) {
                    $stmt = $pdo->prepare("INSERT INTO role_permissions (role, permission_id, granted) VALUES (?, ?, 1)");
                    foreach ($permission_ids as $pid) {
                        $stmt->execute([$role, intval($pid)]);
                    }
                }

                $pdo->commit();
                $role_label = ucfirst(str_replace('_', ' ', $role));
                $success = $role_label . ' permissions updated successfully.';
            } catch (PDOException $e) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
                error_log('[privilege_management] ' . $e->getMessage());
                $error = 'Failed to update permissions.';
            }
        }
    }
}

$selected_role = $_GET['role'] ?? 'admin';
if (!in_array($selected_role, ['super_admin', 'admin', 'user'])) {
    $selected_role = 'admin';
}

$all_permissions = [];
$total_permission_count = 0;
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
    $total_permission_count += count($cat_perms);
}

$current_permissions = [];
try {
    $stmt = $pdo->prepare("SELECT permission_id FROM role_permissions WHERE role = ?");
    $stmt->execute([$selected_role]);
    $current_permissions = array_map('intval', $stmt->fetchAll(PDO::FETCH_COLUMN));
} catch (PDOException $e) {
    $current_permissions = [];
}

$essential_ids_for_role = [];
if (isset($essential_map[$selected_role])) {
    $keys_for_role = $essential_map[$selected_role];
    try {
        $placeholders = implode(',', array_fill(0, count($keys_for_role), '?'));
        $stmt = $pdo->prepare("SELECT id FROM permissions WHERE permission_key IN ($placeholders)");
        $stmt->execute($keys_for_role);
        $essential_ids_for_role = array_map('intval', $stmt->fetchAll(PDO::FETCH_COLUMN));
    } catch (PDOException $e) {
        $essential_ids_for_role = [];
    }
    foreach ($keys_for_role as $role_key) {
        if (isset($essential_fallback_ids[$role_key]) && !in_array($essential_fallback_ids[$role_key], $essential_ids_for_role)) {
            $essential_ids_for_role[] = $essential_fallback_ids[$role_key];
        }
    }
}

$effective_granted = array_unique(array_merge($current_permissions, $essential_ids_for_role));
$granted_count = count($effective_granted);

$role_heading = ucfirst(str_replace('_', ' ', $selected_role));

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
        .perm-grid { display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:0.5rem; }
        .perm-item { display:flex;align-items:center;gap:0.5rem;padding:0.5rem 0.75rem;border-radius:var(--radius);border:1px solid #e5e7eb;background:#f3f4f6;color:#374151;font-size:0.8125rem;cursor:pointer;transition:background 0.15s ease,border-color 0.15s ease; }
        .perm-item:hover { border-color:#9ca3af; }
        .perm-item.active { background:#dcfce7;border-color:#22c55e;color:#14532d; }
        .perm-item.locked { cursor:not-allowed; }
        .perm-item input[type="checkbox"] { accent-color:#16a34a;flex-shrink:0; }
        .perm-lock { margin-left:auto;color:#15803d;font-size:0.6875rem; }
        .perm-required { color:#15803d;font-size:0.6875rem;font-weight:700;font-style:normal;white-space:nowrap; }
        .legend-swatch { display:inline-block;width:14px;height:14px;border-radius:4px;border:1px solid #cbd5e1; }
        .legend-swatch.on { background:#dcfce7;border-color:#22c55e; }
        .legend-swatch.off { background:#f3f4f6; }
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
                    <a href="../admin/registration_approval.php" class="sidebar-link"><i class="fas fa-user-check"></i><span>Registration Approvals</span></a>
                    <a href="privilege_management.php" class="sidebar-link active"><i class="fas fa-shield-alt"></i><span>Privileges</span></a>
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
                    <div><h1 class="page-title">Privilege Management</h1><p class="page-subtitle">Configure role-based permissions</p></div>
                </div>
            </div>

            <div class="content-body">
                <?php if ($success): ?><div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($success); ?></div><?php endif; ?>
                <?php if ($error): ?><div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div><?php endif; ?>

                <div class="card" style="margin-bottom:1.25rem;">
                    <div class="card-body" style="display:flex;flex-wrap:wrap;gap:1rem;align-items:center;justify-content:space-between;">
                        <div style="font-size:0.9375rem;"><i class="fas fa-chart-bar" style="color:var(--primary);"></i> <strong id="grantedCount"><?php echo $granted_count; ?></strong> of <strong id="totalCount"><?php echo $total_permission_count; ?></strong> permissions granted</div>
                        <div style="display:flex;align-items:center;gap:1rem;font-size:0.8125rem;color:#4b5563;">
                            <span style="display:inline-flex;align-items:center;gap:0.375rem;"><span class="legend-swatch on"></span> Green = Active</span>
                            <span style="display:inline-flex;align-items:center;gap:0.375rem;"><span class="legend-swatch off"></span> Gray = Not assigned</span>
                        </div>
                    </div>
                </div>

                <div class="flex gap-3" style="margin-bottom:1.5rem;">
                    <?php foreach (['super_admin', 'admin', 'user'] as $r): ?>
                        <?php $tab_label = ucfirst(str_replace('_', ' ', $r)); ?>
                        <a href="?role=<?php echo $r; ?>" class="btn <?php echo $selected_role === $r ? 'btn-primary' : 'btn-outline'; ?>"><?php echo htmlspecialchars($tab_label); ?></a>
                    <?php endforeach; ?>
                </div>

                <?php if ($selected_role === 'super_admin'): ?>
                    <div class="card"><div class="card-body"><p class="text-muted"><i class="fas fa-info-circle"></i> Super Admins have full access to all features automatically. Permissions cannot be restricted.</p></div></div>
                <?php else: ?>
                    <h2 style="font-size:1.25rem;margin:0 0 0.25rem;"><?php echo htmlspecialchars($role_heading); ?> Permissions</h2>
                    <p class="text-muted" style="margin-bottom:1rem;">Essential permissions are locked and always remain active.</p>
                    <form method="POST" action="">
                        <?php csrf_token_input(); ?>
                        <input type="hidden" name="role" value="<?php echo htmlspecialchars($selected_role); ?>">

                        <?php foreach ($all_permissions as $category => $perms): ?>
                            <?php
                            $category_label = ucfirst($category);
                            $category_slug = strtolower(preg_replace('/[^A-Za-z0-9]+/', '-', $category));
                            ?>
                            <div class="card" style="margin-bottom:1rem;">
                                <div class="card-header" style="display:flex;justify-content:space-between;align-items:center;gap:1rem;">
                                    <h3 class="card-title" style="font-size:0.9375rem;margin:0;"><i class="fas fa-folder"></i> <?php echo htmlspecialchars($category_label); ?></h3>
                                    <label style="display:inline-flex;align-items:center;gap:0.375rem;font-size:0.75rem;font-weight:600;color:#4b5563;cursor:pointer;">
                                        <input type="checkbox" class="select-all-cat" data-target="<?php echo htmlspecialchars($category_slug); ?>" onchange="toggleCategory(this)"> Select All
                                    </label>
                                </div>
                                <div class="card-body" data-category="<?php echo htmlspecialchars($category_slug); ?>">
                                    <div class="perm-grid">
                                    <?php foreach ($perms as $perm): ?>
                                        <?php
                                        $perm_id = intval($perm['id']);
                                        $perm_desc = (isset($perm['description']) && trim($perm['description']) !== '') ? trim($perm['description']) : $perm['permission_key'];
                                        $is_essential = in_array($perm_id, $essential_ids_for_role);
                                        $is_checked = $is_essential || in_array($perm_id, $current_permissions);
                                        ?>
                                        <label class="perm-item<?php echo $is_checked ? ' active' : ''; ?><?php echo $is_essential ? ' locked' : ''; ?>">
                                            <input type="checkbox" class="perm-check" name="permissions[]" value="<?php echo $perm_id; ?>"<?php echo $is_checked ? ' checked' : ''; ?><?php echo $is_essential ? ' disabled' : ''; ?> onchange="onPermChange(this)">
                                            <span><?php echo htmlspecialchars($perm_desc); ?></span>
                                            <?php if ($is_essential): ?>
                                                <i class="fas fa-lock perm-lock"></i>
                                                <em class="perm-required">(Required)</em>
                                            <?php endif; ?>
                                        </label>
                                    <?php endforeach; ?>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>

                        <button type="submit" class="btn btn-primary" style="min-width:200px;"><i class="fas fa-save"></i> Save Permissions</button>
                    </form>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <script>
        function refreshItem(item) {
            var cb = item.querySelector('.perm-check');
            if (cb.checked) { item.classList.add('active'); } else { item.classList.remove('active'); }
        }
        function onPermChange(cb) {
            refreshItem(cb.closest('.perm-item'));
            syncMaster(cb.closest('[data-category]'));
            updateSummary();
        }
        function toggleCategory(master) {
            var box = document.querySelector('.card-body[data-category="' + master.getAttribute('data-target') + '"]');
            if (!box) { return; }
            var boxes = box.querySelectorAll('.perm-check');
            for (var i = 0; i < boxes.length; i++) {
                if (!boxes[i].disabled) { boxes[i].checked = master.checked; }
            }
            var items = box.querySelectorAll('.perm-item');
            for (var j = 0; j < items.length; j++) { refreshItem(items[j]); }
            master.indeterminate = false;
            updateSummary();
        }
        function syncMaster(box) {
            if (!box) { return; }
            var master = document.querySelector('.select-all-cat[data-target="' + box.getAttribute('data-category') + '"]');
            if (!master) { return; }
            var boxes = box.querySelectorAll('.perm-check:not(:disabled)');
            var total = boxes.length, checked = 0;
            for (var i = 0; i < total; i++) { if (boxes[i].checked) { checked++; } }
            master.checked = total > 0 && checked === total;
            master.indeterminate = checked > 0 && checked < total;
        }
        function updateSummary() {
            var granted = document.querySelectorAll('.perm-check:checked').length;
            var total = document.querySelectorAll('.perm-check').length;
            var gEl = document.getElementById('grantedCount');
            var tEl = document.getElementById('totalCount');
            if (gEl) { gEl.textContent = granted; }
            if (tEl) { tEl.textContent = total; }
        }
        (function () {
            var boxes = document.querySelectorAll('.card-body[data-category]');
            for (var i = 0; i < boxes.length; i++) { syncMaster(boxes[i]); }
            updateSummary();
        })();
    </script>

    <div id="sidebarOverlay" class="sidebar-overlay" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('active');"></div>
</body>
</html>
