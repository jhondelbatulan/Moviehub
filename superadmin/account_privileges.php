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

$user_table = ($_GET['table'] ?? $_POST['user_table'] ?? '') === 'admin_users' ? 'admin_users' : 'users';
$target_id = intval($_GET['id'] ?? $_POST['user_id'] ?? 0);

$account = null;
if ($target_id > 0) {
    try {
        if ($user_table === 'users') {
            $stmt = $pdo->prepare("SELECT id, username, email, CONCAT(first_name, ' ', last_name) AS full_name, role, account_status FROM users WHERE id = ?");
        } else {
            $stmt = $pdo->prepare("SELECT id, username, email, full_name, role, account_status FROM admin_users WHERE id = ?");
        }
        $stmt->execute([$target_id]);
        $account = $stmt->fetch();
    } catch (PDOException $e) { error_log('[account_privileges] load: ' . $e->getMessage()); }
}
$load_error = ($account === null || $account === false);

if ($_SERVER['REQUEST_METHOD'] == 'POST' && !$load_error) {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token.';
    } elseif (!check_permission($pdo, 'admin_users', $_SESSION['admin_id'], 'privileges.assign')) {
        $error = 'You do not have permission to assign privileges.';
    } elseif ($account['role'] === 'super_admin') {
        $error = 'Super Admin accounts always have full access; overrides cannot be applied.';
    } else {
        $requested = isset($_POST['permissions']) && is_array($_POST['permissions']) ? array_map('intval', $_POST['permissions']) : [];
        try {
            $stmt = $pdo->prepare("SELECT permission_id, granted FROM role_permissions WHERE role = ?");
            $stmt->execute([$account['role']]);
            $baseline = [];
            foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) { $baseline[(int)$row['permission_id']] = (bool)$row['granted']; }

            $essential_keys = $essential_map[$account['role']] ?? ['dashboard.view'];
            $placeholders = implode(',', array_fill(0, count($essential_keys), '?'));
            $stmt = $pdo->prepare("SELECT id FROM permissions WHERE permission_key IN ($placeholders)");
            $stmt->execute($essential_keys);
            $essential_ids = array_map('intval', $stmt->fetchAll(PDO::FETCH_COLUMN));
            foreach ($essential_keys as $ek) {
                if (isset($essential_fallback_ids[$ek]) && !in_array($essential_fallback_ids[$ek], $essential_ids)) {
                    $essential_ids[] = $essential_fallback_ids[$ek];
                }
            }

            $all_perm_ids = array_map('intval', $pdo->query("SELECT id FROM permissions")->fetchAll(PDO::FETCH_COLUMN));

            $pdo->beginTransaction();
            $upsert = $pdo->prepare("INSERT INTO user_permissions (user_table, user_id, permission_id, granted) VALUES (?, ?, ?, ?)");
            $del = $pdo->prepare("DELETE FROM user_permissions WHERE user_table = ? AND user_id = ? AND permission_id = ?");
            $applied = 0;
            foreach ($all_perm_ids as $pid) {
                $want = in_array($pid, $requested, true) || in_array($pid, $essential_ids, true);
                $base = isset($baseline[$pid]) ? $baseline[$pid] : false;
                if ($want === $base) {
                    $del->execute([$user_table, $target_id, $pid]);
                } else {
                    $del->execute([$user_table, $target_id, $pid]);
                    $upsert->execute([$user_table, $target_id, $pid, $want ? 1 : 0]);
                    $applied++;
                }
            }
            $pdo->commit();

            log_audit($pdo, 'privileges.assign', $user_table, $target_id, $account['username'], "overrides=$applied");
            $success = 'Privileges updated for ' . htmlspecialchars($account['full_name']) . ($applied > 0 ? " ($applied custom override" . ($applied == 1 ? '' : 's') . ')' : ' (matches role defaults).');
        } catch (PDOException $e) {
            if ($pdo->inTransaction()) { $pdo->rollBack(); }
            error_log('[account_privileges] save: ' . $e->getMessage());
            $error = 'Failed to update privileges.';
        }
    }
}

$all_permissions = [];
$total_permission_count = 0;
try {
    $all_perms_raw = $pdo->query("SELECT * FROM permissions ORDER BY category, permission_key")->fetchAll(PDO::FETCH_ASSOC);
    foreach ($all_perms_raw as $perm_row) {
        $category_name = (isset($perm_row['category']) && trim($perm_row['category']) !== '') ? trim($perm_row['category']) : 'Other';
        $all_permissions[$category_name][] = $perm_row;
    }
} catch (PDOException $e) { $all_permissions = []; }
foreach ($all_permissions as $cat_perms) { $total_permission_count += count($cat_perms); }

$baseline = [];
$overrides = [];
$essential_ids_for_account = [];
if (!$load_error) {
    try {
        $stmt = $pdo->prepare("SELECT permission_id, granted FROM role_permissions WHERE role = ?");
        $stmt->execute([$account['role']]);
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) { $baseline[(int)$row['permission_id']] = (bool)$row['granted']; }
    } catch (PDOException $e) {}
    try {
        $stmt = $pdo->prepare("SELECT permission_id, granted FROM user_permissions WHERE user_table = ? AND user_id = ?");
        $stmt->execute([$user_table, $target_id]);
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) { $overrides[(int)$row['permission_id']] = (bool)$row['granted']; }
    } catch (PDOException $e) {}
    $keys_for_role = $essential_map[$account['role']] ?? ['dashboard.view'];
    try {
        $placeholders = implode(',', array_fill(0, count($keys_for_role), '?'));
        $stmt = $pdo->prepare("SELECT id FROM permissions WHERE permission_key IN ($placeholders)");
        $stmt->execute($keys_for_role);
        $essential_ids_for_account = array_map('intval', $stmt->fetchAll(PDO::FETCH_COLUMN));
    } catch (PDOException $e) {}
    foreach ($keys_for_role as $rk) {
        if (isset($essential_fallback_ids[$rk]) && !in_array($essential_fallback_ids[$rk], $essential_ids_for_account)) {
            $essential_ids_for_account[] = $essential_fallback_ids[$rk];
        }
    }
}

$effective_count = 0;
if (!$load_error) {
    foreach ($all_permissions as $cat_perms) {
        foreach ($cat_perms as $perm) {
            $pid = intval($perm['id']);
            if (in_array($pid, $essential_ids_for_account, true)) { $effective_count++; continue; }
            $eff = array_key_exists($pid, $overrides) ? $overrides[$pid] : (isset($baseline[$pid]) ? $baseline[$pid] : false);
            if ($eff) { $effective_count++; }
        }
    }
}

generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Account Privileges - MovieHub</title>
    <link rel="stylesheet" href="../assets/css/style.css?v=2.3.0">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        .perm-grid { display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:0.5rem; }
        .perm-item { display:flex;align-items:center;gap:0.5rem;padding:0.5rem 0.75rem;border-radius:var(--radius);border:1px solid var(--border);background:var(--surface-2);color:var(--text);font-size:0.8125rem;cursor:pointer;transition:border-color 0.15s ease,background 0.15s ease; }
        .perm-item:hover { border-color:var(--primary); }
        .perm-item.active { background:rgba(240,180,41,0.10);border-color:var(--primary); }
        .perm-item.locked { cursor:not-allowed;opacity:0.85; }
        .perm-item input[type="checkbox"] { accent-color:var(--primary);flex-shrink:0; }
        .perm-lock { margin-left:auto;color:var(--primary);font-size:0.6875rem; }
        .perm-src { margin-left:auto;font-size:0.6875rem;font-weight:700;white-space:nowrap;color:var(--muted); }
        .perm-src.grant { color:var(--success); }
        .perm-src.deny { color:var(--danger); }
    </style>
</head>
<body>
    <div class="page-wrapper">
        <aside class="sidebar" id="sidebar">
            <div class="sidebar-header"><a href="dashboard.php" class="sidebar-logo"><i class="fas fa-film"></i><span>MovieHub</span></a></div>
            <nav class="sidebar-nav">
<?php require __DIR__ . '/../includes/sidebar_navigation.php'; ?>
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
                    <div><h1 class="page-title">Account Privileges</h1><p class="page-subtitle">Assign per-account permission overrides</p></div>
                </div>
            </div>

            <div class="content-body">
                <?php if ($success): ?><div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($success); ?></div><?php endif; ?>
                <?php if ($error): ?><div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div><?php endif; ?>

                <?php if ($load_error): ?>
                    <div class="card"><div class="empty-state"><i class="fas fa-user-slash"></i><h3>Account Not Found</h3><p>The requested account does not exist.</p>
                    <a href="account_management.php" class="btn btn-primary btn-sm" style="margin-top:0.75rem;"><i class="fas fa-arrow-left"></i> Back to Account Management</a></div></div>
                <?php else: ?>
                <div class="card" style="margin-bottom:1.25rem;">
                    <div class="card-body" style="display:flex;flex-wrap:wrap;gap:1rem;align-items:center;justify-content:space-between;">
                        <div style="display:flex;align-items:center;gap:0.75rem;">
                            <div class="avatar avatar-sm" style="background:var(--primary);color:white;"><?php echo strtoupper(substr($account['full_name'], 0, 1)); ?></div>
                            <div>
                                <strong><?php echo htmlspecialchars($account['full_name']); ?></strong> <small class="text-muted">@<?php echo htmlspecialchars($account['username']); ?></small><br>
                                <?php echo render_role_badge($account['role']); ?> <?php echo render_status_badge($account['account_status']); ?>
                                <small class="text-muted"><?php echo $user_table === 'users' ? 'Customer account' : 'Admin account'; ?></small>
                            </div>
                        </div>
                        <div style="display:flex;align-items:center;gap:1rem;">
                            <div style="font-size:0.9375rem;"><i class="fas fa-chart-bar" style="color:var(--primary);"></i> <strong id="grantedCount"><?php echo $effective_count; ?></strong> of <strong id="totalCount"><?php echo $total_permission_count; ?></strong> granted</div>
                            <a href="account_management.php?tab=<?php echo $user_table === 'users' ? 'users' : 'admins'; ?>" class="btn btn-outline btn-sm"><i class="fas fa-arrow-left"></i> Back</a>
                        </div>
                    </div>
                </div>

                <?php if ($account['role'] === 'super_admin'): ?>
                    <div class="card"><div class="card-body"><p class="text-muted"><i class="fas fa-info-circle"></i> This account is a Super Admin and automatically has full access to all features. Per-account overrides do not apply.</p></div></div>
                <?php else: ?>
                <p class="text-muted" style="margin-bottom:1rem;">Checked = allowed for this account. Unchecking a role default creates a denial override; checking a non-default permission grants it to this account only. Essential permissions are locked.</p>
                <form method="POST" action="">
                    <?php csrf_token_input(); ?>
                    <input type="hidden" name="user_table" value="<?php echo htmlspecialchars($user_table); ?>">
                    <input type="hidden" name="user_id" value="<?php echo $target_id; ?>">
                    <?php foreach ($all_permissions as $category => $perms): ?>
                        <?php
                        $category_label = ucfirst($category);
                        $category_slug = strtolower(preg_replace('/[^A-Za-z0-9]+/', '-', $category));
                        ?>
                        <div class="card" style="margin-bottom:1rem;">
                            <div class="card-header" style="display:flex;justify-content:space-between;align-items:center;gap:1rem;">
                                <h3 class="card-title" style="font-size:0.9375rem;margin:0;"><i class="fas fa-folder"></i> <?php echo htmlspecialchars($category_label); ?></h3>
                                <label style="display:inline-flex;align-items:center;gap:0.375rem;font-size:0.75rem;font-weight:600;color:var(--text-light);cursor:pointer;">
                                    <input type="checkbox" data-target="<?php echo htmlspecialchars($category_slug); ?>" onchange="toggleCategory(this)"> Select All
                                </label>
                            </div>
                            <div class="card-body" data-category="<?php echo htmlspecialchars($category_slug); ?>">
                                <div class="perm-grid">
                                <?php foreach ($perms as $perm): ?>
                                    <?php
                                    $pid = intval($perm['id']);
                                    $desc = (isset($perm['description']) && trim($perm['description']) !== '') ? trim($perm['description']) : $perm['permission_key'];
                                    $is_essential = in_array($pid, $essential_ids_for_account, true);
                                    $base = isset($baseline[$pid]) ? $baseline[$pid] : false;
                                    $has_override = array_key_exists($pid, $overrides);
                                    $effective = $has_override ? $overrides[$pid] : $base;
                                    ?>
                                    <label class="perm-item<?php echo $effective ? ' active' : ''; ?><?php echo $is_essential ? ' locked' : ''; ?>">
                                        <input type="checkbox" name="permissions[]" value="<?php echo $pid; ?>"<?php echo $effective ? ' checked' : ''; ?><?php echo $is_essential ? ' disabled' : ''; ?> onchange="onPermChange(this)">
                                        <span><?php echo htmlspecialchars($desc); ?></span>
                                        <?php if ($has_override && !$is_essential): ?><em class="perm-src<?php echo $overrides[$pid] ? ' grant' : ' deny'; ?>"><?php echo $overrides[$pid] ? 'Granted' : 'Denied'; ?></em>
                                        <?php elseif ($is_essential): ?><i class="fas fa-lock perm-lock"></i>
                                        <?php else: ?><em class="perm-src">Role</em><?php endif; ?>
                                    </label>
                                <?php endforeach; ?>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                    <button type="submit" class="btn btn-primary" style="min-width:220px;"><i class="fas fa-save"></i> Save Privileges</button>
                </form>
                <?php endif; ?>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <div id="sidebarOverlay" class="sidebar-overlay" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('active');"></div>

    <script>
        function refreshItem(item) {
            var cb = item.querySelector('.perm-check, input[type="checkbox"]');
            if (!cb || cb.disabled) return;
            if (cb.checked) { item.classList.add('active'); } else { item.classList.remove('active'); }
        }
        function onPermChange(cb) {
            refreshItem(cb.closest('.perm-item'));
            syncMaster(cb.closest('[data-category]'));
        }
        function toggleCategory(master) {
            var box = document.querySelector('.card-body[data-category="' + master.getAttribute('data-target') + '"]');
            if (!box) return;
            var boxes = box.querySelectorAll('.perm-item input[type="checkbox"]');
            for (var i = 0; i < boxes.length; i++) {
                if (!boxes[i].disabled) { boxes[i].checked = master.checked; }
            }
            var items = box.querySelectorAll('.perm-item');
            for (var j = 0; j < items.length; j++) { refreshItem(items[j]); }
            master.indeterminate = false;
        }
        function syncMaster(box) {
            if (!box) return;
            var master = document.querySelector('input[type="checkbox"][data-target="' + box.getAttribute('data-category') + '"]');
            if (!master) return;
            var boxes = box.querySelectorAll('.perm-item input[type="checkbox"]:not(:disabled)');
            var total = boxes.length, checked = 0;
            for (var i = 0; i < total; i++) { if (boxes[i].checked) checked++; }
            master.checked = total > 0 && checked === total;
            master.indeterminate = checked > 0 && checked < total;
        }
        (function () {
            var boxes = document.querySelectorAll('.card-body[data-category]');
            for (var i = 0; i < boxes.length; i++) { syncMaster(boxes[i]); }
        })();
    </script>
</body>
</html>
