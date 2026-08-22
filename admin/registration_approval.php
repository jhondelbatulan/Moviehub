<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/authorization.php';
require_once '../includes/csrf.php';

require_login();
require_role(['admin', 'super_admin']);
require_permission('registrations.view');

$success = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token. Please try again.';
    } else {
        $action = $_POST['action'] ?? '';
        $user_id = intval($_POST['user_id'] ?? 0);
        $admin_notes = trim($_POST['admin_notes'] ?? '');

        if ($user_id > 0 && in_array($action, ['approve', 'reject'])) {
            try {
                $pdo->beginTransaction();

                $stmt = $pdo->prepare("SELECT ra.id, ra.status, u.username, u.email, u.first_name, u.last_name FROM registration_approvals ra JOIN users u ON ra.user_id = u.id WHERE ra.user_id = ? AND ra.status = 'pending'");
                $stmt->execute([$user_id]);
                $approval = $stmt->fetch();

                if (!$approval) {
                    $error = 'Registration not found or already processed.';
                    $pdo->rollBack();
                } else {
                    $new_status = ($action === 'approve') ? STATUS_APPROVED : STATUS_REJECTED;

                    $reviewed_by_table = isset($_SESSION['admin_id']) ? 'admin_users' : null;
                    $stmt = $pdo->prepare("UPDATE registration_approvals SET status = ?, reviewed_by_table = ?, reviewed_by_id = ?, rejection_reason = ?, reviewed_at = NOW() WHERE id = ?");
                    $stmt->execute([$new_status, $reviewed_by_table, $_SESSION['admin_id'], $admin_notes, $approval['id']]);

                    $stmt = $pdo->prepare("UPDATE users SET account_status = ? WHERE id = ?");
                    $stmt->execute([$new_status, $user_id]);

                    record_status_change($pdo, 'users', $user_id, STATUS_PENDING, $new_status, $admin_notes);

                    $pdo->commit();

                    $full_name = htmlspecialchars($approval['first_name'] . ' ' . $approval['last_name']);
                    $success = "Registration for $full_name has been " . $new_status . ".";
                }
            } catch (PDOException $e) {
                $pdo->rollBack();
                error_log('[registration_approval] ' . $e->getMessage());
                $error = 'An error occurred. Please try again.';
            }
        }
    }
}

$search = trim($_GET['search'] ?? '');
$status_filter = $_GET['status'] ?? '';
$date_from = $_GET['date_from'] ?? '';
$date_to = $_GET['date_to'] ?? '';
if (!in_array($status_filter, ['', 'pending', 'approved', 'rejected'], true)) { $status_filter = ''; }

$page = max(1, intval($_GET['page'] ?? 1));
$ppage = max(1, intval($_GET['ppage'] ?? 1));
$per_page = RECORDS_PER_PAGE;

try { $pending_count_all = (int)$pdo->query("SELECT COUNT(*) FROM registration_approvals WHERE status = 'pending'")->fetchColumn(); } catch (PDOException $e) { $pending_count_all = 0; }
try { $processed_count_all = (int)$pdo->query("SELECT COUNT(*) FROM registration_approvals WHERE status != 'pending'")->fetchColumn(); } catch (PDOException $e) { $processed_count_all = 0; }

$like = '%' . $search . '%';

$view = $_GET['view'] ?? '';
if (!in_array($view, ['pending', 'history'], true)) {
    $view = ($status_filter === 'approved' || $status_filter === 'rejected') ? 'history' : 'pending';
}
$show_pending = ($view === 'pending');
$show_processed = ($view === 'history');

$pending_approvals = [];
$pagination_pending = ['per_page' => $per_page, 'offset' => 0, 'total_pages' => 1];

if ($show_pending) {
    $w = ["ra.status = 'pending'"]; $p = [];
    if ($search !== '') { $w[] = "(u.username LIKE ? OR u.email LIKE ? OR u.first_name LIKE ? OR u.last_name LIKE ? OR u.id_number LIKE ?)"; array_push($p, $like, $like, $like, $like, $like); }
    if ($date_from !== '') { $w[] = "ra.created_at >= ?"; $p[] = $date_from . ' 00:00:00'; }
    if ($date_to !== '') { $w[] = "ra.created_at <= ?"; $p[] = $date_to . ' 23:59:59'; }
    try {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM registration_approvals ra JOIN users u ON ra.user_id = u.id WHERE " . implode(' AND ', $w));
        $stmt->execute($p);
        $filtered_total = (int)$stmt->fetchColumn();
    } catch (PDOException $e) { error_log('[registration_approval] ' . $e->getMessage()); $filtered_total = 0; }
    $pagination_pending = paginate($filtered_total, $page, $per_page);
    try {
        $stmt = $pdo->prepare("
            SELECT ra.*, u.id as uid, u.username, u.email, u.first_name, u.last_name, u.id_number, u.employee_id,
                   u.sex, u.birthdate, u.contact_number, u.address_street, u.address_barangay, u.address_city,
                   u.address_province, u.address_country, u.zip_code
            FROM registration_approvals ra
            JOIN users u ON ra.user_id = u.id
            WHERE " . implode(' AND ', $w) . "
            ORDER BY ra.created_at ASC
            LIMIT {$pagination_pending['per_page']} OFFSET {$pagination_pending['offset']}
        ");
        $stmt->execute($p);
        $pending_approvals = $stmt->fetchAll();
    } catch (PDOException $e) { error_log('[registration_approval] ' . $e->getMessage()); }
}

$processed_approvals = [];
$pagination_processed = ['per_page' => $per_page, 'offset' => 0, 'total_pages' => 1];
$processed_total = 0;

if ($show_processed && $status_filter !== 'pending') {
    $w = ["ra.status != 'pending'"]; $p = [];
    if ($status_filter !== '') { $w[] = "ra.status = ?"; $p[] = $status_filter; }
    if ($search !== '') { $w[] = "(u.username LIKE ? OR u.email LIKE ? OR u.first_name LIKE ? OR u.last_name LIKE ? OR u.id_number LIKE ?)"; array_push($p, $like, $like, $like, $like, $like); }
    if ($date_from !== '') { $w[] = "ra.reviewed_at >= ?"; $p[] = $date_from . ' 00:00:00'; }
    if ($date_to !== '') { $w[] = "ra.reviewed_at <= ?"; $p[] = $date_to . ' 23:59:59'; }
    try {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM registration_approvals ra JOIN users u ON ra.user_id = u.id WHERE " . implode(' AND ', $w));
        $stmt->execute($p);
        $processed_total = (int)$stmt->fetchColumn();
    } catch (PDOException $e) { error_log('[registration_approval] ' . $e->getMessage()); $processed_total = 0; }
    $pagination_processed = paginate($processed_total, $ppage, $per_page);
    try {
        $stmt = $pdo->prepare("
            SELECT ra.*, u.username, u.email, u.first_name, u.last_name, u.id_number, u.employee_id,
                   au.full_name as reviewed_by_name
            FROM registration_approvals ra
            JOIN users u ON ra.user_id = u.id
            LEFT JOIN admin_users au ON ra.reviewed_by_id = au.id
            WHERE " . implode(' AND ', $w) . "
            ORDER BY COALESCE(ra.reviewed_at, ra.created_at) DESC
            LIMIT {$pagination_processed['per_page']} OFFSET {$pagination_processed['offset']}
        ");
        $stmt->execute($p);
        $processed_approvals = $stmt->fetchAll();
    } catch (PDOException $e) { error_log('[registration_approval] ' . $e->getMessage()); }
}

generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registration Approval - MovieHub</title>
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
                    <a href="registration_approval.php" class="sidebar-link active"><i class="fas fa-user-check"></i><span>Registration Approvals</span></a>
                    <a href="../superadmin/privilege_management.php" class="sidebar-link"><i class="fas fa-shield-alt"></i><span>Privileges</span></a>
                    <a href="../superadmin/deletion_requests.php" class="sidebar-link"><i class="fas fa-user-minus"></i><span>Deletion Requests</span></a>
                </div>
                <div class="sidebar-section"><div class="sidebar-section-title">Activity</div>
                    <a href="login_logs.php" class="sidebar-link"><i class="fas fa-history"></i><span>Login Logs</span></a>
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
                    <a href="registration_approval.php" class="sidebar-link active"><i class="fas fa-user-check"></i><span>Approvals</span></a>
                    <a href="login_logs.php" class="sidebar-link"><i class="fas fa-history"></i><span>Login Logs</span></a>
                </div>
<?php endif; ?>
                <div class="sidebar-section"><div class="sidebar-section-title">Account</div>
                    <a href="../client/logout.php" class="sidebar-link"><i class="fas fa-sign-out-alt"></i><span>Logout</span></a>
                </div>
            </nav>
            <div class="sidebar-user">
                <div class="avatar avatar-sm" style="background:var(--primary);color:white;"><?php echo strtoupper(substr($_SESSION['admin_full_name'], 0, 1)); ?></div>
                <div class="sidebar-user-info">
                    <div class="sidebar-user-name"><?php echo htmlspecialchars($_SESSION['admin_full_name']); ?></div>
                    <div class="sidebar-user-role" style="color:var(--primary);font-weight:600;"><?php echo ($_SESSION['admin_role'] ?? '') === 'super_admin' ? 'Super Admin' : ucfirst(str_replace('_', ' ', $_SESSION['admin_role'] ?? 'admin')); ?></div>
                </div>
            </div>
        </aside>

        <div class="main-content">
            <div class="top-header">
                <div class="flex items-center gap-3">
                    <button class="sidebar-toggle" onclick="document.getElementById('sidebar').classList.toggle('open');document.getElementById('sidebarOverlay').classList.toggle('active');"><i class="fas fa-bars"></i></button>
                    <div><h1 class="page-title">Registration Approvals</h1><p class="page-subtitle">Review and approve pending user registrations</p></div>
                </div>
                <div class="header-actions"><span class="badge badge-warning" style="font-size:0.875rem;"><?php echo $pending_count_all; ?> Pending</span></div>
            </div>

            <div class="content-body">
                <?php if ($success): ?><div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($success); ?></div><?php endif; ?>
                <?php if ($error): ?><div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div><?php endif; ?>

                <div style="display:flex;gap:0.75rem;margin-bottom:1rem;flex-wrap:wrap;">
                    <?php
                    $tabBase = $_GET; unset($tabBase['page'], $tabBase['ppage'], $tabBase['view']);
                    $tabPendingQ = http_build_query(array_merge($tabBase, ['view' => 'pending']));
                    $tabHistoryQ = http_build_query(array_merge($tabBase, ['view' => 'history']));
                    ?>
                    <a href="?<?php echo $tabPendingQ; ?>" class="btn <?php echo $view === 'pending' ? 'btn-primary' : 'btn-outline'; ?>"><i class="fas fa-user-clock"></i> Pending Registrations (<?php echo number_format($pending_count_all); ?>)</a>
                    <a href="?<?php echo $tabHistoryQ; ?>" class="btn <?php echo $view === 'history' ? 'btn-primary' : 'btn-outline'; ?>"><i class="fas fa-history"></i> Decision History (<?php echo number_format($processed_count_all); ?>)</a>
                </div>

                <div class="card" style="margin-bottom:1.5rem;">
                    <div class="card-body" style="padding:1rem 1.5rem;">
                        <form method="GET" action="" class="flex items-center gap-3" style="flex-wrap:wrap;">
                            <div class="form-group" style="flex:1;min-width:180px;margin-bottom:0;">
                                <input type="text" name="search" class="form-control" placeholder="Search name, username, email, ID number..." value="<?php echo htmlspecialchars($search); ?>">
                            </div>
                            <div class="form-group" style="flex:0 0 150px;margin-bottom:0;">
                                <select name="status" class="form-control">
                                    <option value="">All Statuses</option>
                                    <option value="pending" <?php echo $status_filter==='pending'?'selected':''; ?>>Pending</option>
                                    <option value="approved" <?php echo $status_filter==='approved'?'selected':''; ?>>Approved</option>
                                    <option value="rejected" <?php echo $status_filter==='rejected'?'selected':''; ?>>Rejected</option>
                                </select>
                            </div>
                            <div class="form-group" style="flex:0 0 140px;margin-bottom:0;">
                                <input type="date" name="date_from" class="form-control" value="<?php echo htmlspecialchars($date_from); ?>">
                            </div>
                            <div class="form-group" style="flex:0 0 140px;margin-bottom:0;">
                                <input type="date" name="date_to" class="form-control" value="<?php echo htmlspecialchars($date_to); ?>">
                            </div>
                            <button type="submit" class="btn btn-primary btn-sm"><i class="fas fa-search"></i> Filter</button>
                            <a href="registration_approval.php" class="btn btn-outline btn-sm"><i class="fas fa-times"></i> Clear</a>
                        </form>
                    </div>
                </div>

                <?php if ($show_pending): ?>
                <h3 style="margin:0 0 1rem;"><i class="fas fa-user-clock"></i> Pending Registrations<?php echo isset($filtered_total) ? ' <span class="text-muted text-sm">(' . number_format($filtered_total) . ')</span>' : ''; ?></h3>
                <?php if (empty($pending_approvals)): ?>
                    <div class="card"><div class="empty-state"><i class="fas fa-user-check"></i><h3>No Pending Registrations</h3><p>All registrations have been reviewed.</p></div></div>
                <?php else: ?>
                    <?php foreach ($pending_approvals as $reg): ?>
                    <div class="card" style="margin-bottom:1rem;">
                        <div class="card-header">
                            <h3 class="card-title"><i class="fas fa-user"></i> <?php echo htmlspecialchars($reg['first_name'].' '.$reg['last_name']); ?></h3>
                            <span class="text-sm text-muted">Applied: <?php echo date('M d, Y H:i', strtotime($reg['created_at'])); ?></span>
                        </div>
                        <div class="card-body">
                            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:0.75rem;margin-bottom:1rem;">
                                <div><strong>Username:</strong> <?php echo htmlspecialchars($reg['username']); ?></div>
                                <div><strong>Email:</strong> <?php echo htmlspecialchars($reg['email']); ?></div>
                                <div><strong>ID Number:</strong> <?php echo htmlspecialchars($reg['id_number']); ?></div>
                                <div><strong>Employee ID:</strong> <?php echo htmlspecialchars($reg['employee_id']); ?></div>
                                <div><strong>Sex:</strong> <?php echo htmlspecialchars($reg['sex']); ?></div>
                                <div><strong>Birthdate:</strong> <?php echo htmlspecialchars($reg['birthdate']); ?></div>
                                <div><strong>Contact:</strong> <?php echo htmlspecialchars($reg['contact_number']); ?></div>
                                <div><strong>Address:</strong> <?php echo htmlspecialchars(implode(', ', array_filter([$reg['address_street'], $reg['address_barangay'], $reg['address_city'], $reg['address_province'], $reg['address_country'], $reg['zip_code']]))); ?></div>
                            </div>

                            <form method="POST" action="" style="margin-top:1rem;">
                                <?php csrf_token_input(); ?>
                                <input type="hidden" name="user_id" value="<?php echo $reg['uid']; ?>">
                                <div class="form-group">
                                    <label>Admin Notes (optional)</label>
                                    <textarea name="admin_notes" class="form-control" rows="2" placeholder="Add notes about this decision..."></textarea>
                                </div>
                                <div class="flex gap-3">
                                    <button type="submit" name="action" value="approve" class="btn btn-success" style="flex:1;"><i class="fas fa-check"></i> Approve</button>
                                    <button type="submit" name="action" value="reject" class="btn btn-danger" style="flex:1;"><i class="fas fa-times"></i> Reject</button>
                                </div>
                            </form>
                        </div>
                    </div>
                    <?php endforeach; ?>
                <?php endif; ?>

                <?php if ($pagination_pending['total_pages'] > 1): ?>
                <div class="pagination" style="justify-content:center;margin:1.25rem 0;">
                    <?php
                    $bp = $_GET; unset($bp['ppage']);
                    if ($page > 1) { $bp['page'] = $page - 1; echo '<a href="?' . http_build_query($bp) . '" class="btn btn-outline btn-sm"><i class="fas fa-chevron-left"></i> Prev</a>'; }
                    $start = max(1, $page - 2); $end = min($pagination_pending['total_pages'], $page + 2);
                    for ($i = $start; $i <= $end; $i++) { $bp['page'] = $i; echo '<a href="?' . http_build_query($bp) . '" class="btn ' . ($i === $page ? 'btn-primary' : 'btn-outline') . ' btn-sm">' . $i . '</a>'; }
                    if ($page < $pagination_pending['total_pages']) { $bp['page'] = $page + 1; echo '<a href="?' . http_build_query($bp) . '" class="btn btn-outline btn-sm">Next <i class="fas fa-chevron-right"></i></a>'; }
                    ?>
                </div>
                <?php endif; ?>
                <?php endif; ?>

                <?php if ($show_processed): ?>
                <h3 style="margin:1.5rem 0 1rem;"><i class="fas fa-history"></i> Decision History<?php echo ' <span class="text-muted text-sm">(' . number_format($processed_total) . ')</span>'; ?></h3>
                <?php if (empty($processed_approvals)): ?>
                    <div class="card"><div class="empty-state"><i class="fas fa-history"></i><h3>No Decisions Found</h3><p>No processed registrations match your filters.</p></div></div>
                <?php else: ?>
                <div class="card">
                    <div class="table-responsive">
                        <table class="table">
                            <thead><tr><th>User</th><th>Email</th><th>Status</th><th>Reviewed By</th><th>Date</th><th>Notes</th></tr></thead>
                            <tbody>
<?php foreach ($processed_approvals as $proc): ?>
                                <tr>
                                    <td><strong><?php echo htmlspecialchars($proc['first_name'].' '.$proc['last_name']); ?></strong><br><small class="text-muted"><?php echo htmlspecialchars($proc['username']); ?></small></td>
                                    <td><?php echo htmlspecialchars($proc['email']); ?></td>
                                    <td><?php echo render_status_badge($proc['status']); ?></td>
                                    <td><?php echo htmlspecialchars($proc['reviewed_by_name'] ?? 'System'); ?></td>
                                    <td><?php echo date('M d, Y H:i', strtotime($proc['reviewed_at'])); ?></td>
                                    <td><small><?php echo !empty($proc['rejection_reason']) ? htmlspecialchars($proc['rejection_reason']) : '-'; ?></small></td>
                                </tr>
<?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
                <?php if ($pagination_processed['total_pages'] > 1): ?>
                <div class="pagination" style="justify-content:center;margin-top:1.25rem;">
                    <?php
                    $bp = $_GET; unset($bp['page']);
                    if ($ppage > 1) { $bp['ppage'] = $ppage - 1; echo '<a href="?' . http_build_query($bp) . '" class="btn btn-outline btn-sm"><i class="fas fa-chevron-left"></i> Prev</a>'; }
                    $start = max(1, $ppage - 2); $end = min($pagination_processed['total_pages'], $ppage + 2);
                    for ($i = $start; $i <= $end; $i++) { $bp['ppage'] = $i; echo '<a href="?' . http_build_query($bp) . '" class="btn ' . ($i === $ppage ? 'btn-primary' : 'btn-outline') . ' btn-sm">' . $i . '</a>'; }
                    if ($ppage < $pagination_processed['total_pages']) { $bp['ppage'] = $ppage + 1; echo '<a href="?' . http_build_query($bp) . '" class="btn btn-outline btn-sm">Next <i class="fas fa-chevron-right"></i></a>'; }
                    ?>
                </div>
                <?php endif; ?>
                <?php endif; ?>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <div id="sidebarOverlay" class="sidebar-overlay" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('active');"></div>
</body>
</html>
