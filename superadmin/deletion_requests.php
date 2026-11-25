<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/authorization.php';
require_once '../includes/csrf.php';

require_login();
require_role('super_admin');
require_permission('deletion_requests.view');

$success = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token.';
    } else {
        $action = $_POST['action'] ?? '';
        $request_id = intval($_POST['request_id'] ?? 0);
        $admin_notes = trim($_POST['admin_notes'] ?? '');

        try {
            if ($action === 'approve') {
                $stmt = $pdo->prepare("SELECT id, target_table, target_id, target_name FROM deletion_requests WHERE id = ? AND status = 'pending'");
                $stmt->execute([$request_id]);
                $req = $stmt->fetch();
                if ($req) {
                    $pdo->beginTransaction();
                    try {
                        $info = hard_delete_account($pdo, $req['target_table'], $req['target_id'], true);
                        $stmt = $pdo->prepare("UPDATE deletion_requests SET status = 'approved', reviewed_by_id = ?, reviewed_by_name = ?, rejection_reason = ?, reviewed_at = NOW() WHERE id = ?");
                        $stmt->execute([$_SESSION['admin_id'], $_SESSION['admin_full_name'] ?? '', $admin_notes, $request_id]);
                        $pdo->prepare("INSERT INTO activity_logs (admin_id, admin_username, action, target_type, target_id, target_name, reason, ip_address) VALUES (?, ?, 'delete_approve', ?, ?, ?, ?, ?)")
                            ->execute([$_SESSION['admin_id'], $_SESSION['admin_username'], $req['target_table'], $req['target_id'], $info['full_name'], $admin_notes, $_SERVER['REMOTE_ADDR'] ?? '']);
                        log_audit($pdo, 'delete_approve', $req['target_table'], $req['target_id'], $info['full_name'], 'Deletion request approved and account permanently deleted');
                        $pdo->commit();
                        $success = 'Deletion request approved. The account row (' . htmlspecialchars($info['full_name']) . ') has been permanently deleted from the database.';
                    } catch (PDOException $e) {
                        $pdo->rollBack();
                        error_log('[deletion_requests] ' . $e->getMessage());
                        $error = 'Failed to delete the account from the database.';
                    }
                } else {
                    $error = 'Request not found or already processed.';
                }
            } elseif ($action === 'reject') {
$stmt = $pdo->prepare("UPDATE deletion_requests SET status = 'rejected', reviewed_by_id = ?, reviewed_by_name = ?, rejection_reason = ?, reviewed_at = NOW() WHERE id = ? AND status = 'pending'");
                $stmt->execute([$_SESSION['admin_id'], $_SESSION['admin_full_name'] ?? '', $admin_notes, $request_id]);
                $stmt2 = $pdo->prepare("SELECT target_table, target_id, target_name FROM deletion_requests WHERE id = ?");
                $stmt2->execute([$request_id]);
                $rreq = $stmt2->fetch();
                if ($rreq) log_audit($pdo, 'delete_reject', $rreq['target_table'], $rreq['target_id'], $rreq['target_name'], 'Deletion request rejected');
                $success = 'Deletion request rejected.';
            }
        } catch (PDOException $e) {
            $pdo->rollBack();
            error_log('[deletion_requests] ' . $e->getMessage());
            $error = 'An error occurred.';
        }
    }
}

$pending = [];
$processed = [];
try {
    $pending = $pdo->prepare("
        SELECT dr.*, 
            COALESCE(
                CASE dr.target_table 
                    WHEN 'users' THEN (SELECT CONCAT(first_name,' ',last_name) FROM users WHERE id = dr.target_id)
                    WHEN 'admin_users' THEN (SELECT full_name FROM admin_users WHERE id = dr.target_id)
                END, dr.target_name) as full_name,
            CASE dr.target_table 
                WHEN 'users' THEN (SELECT username FROM users WHERE id = dr.target_id)
                WHEN 'admin_users' THEN (SELECT username FROM admin_users WHERE id = dr.target_id)
            END as username
        FROM deletion_requests dr
        WHERE dr.status = 'pending'
        ORDER BY dr.created_at ASC
    ");
    $pending->execute();
    $pending = $pending->fetchAll();
} catch (PDOException $e) { $pending = []; }

try {
    $processed = $pdo->prepare("
        SELECT dr.*, 
            COALESCE(
                CASE dr.target_table 
                    WHEN 'users' THEN (SELECT CONCAT(first_name,' ',last_name) FROM users WHERE id = dr.target_id)
                    WHEN 'admin_users' THEN (SELECT full_name FROM admin_users WHERE id = dr.target_id)
                END, dr.target_name) as full_name,
            au.full_name as reviewed_by_name
        FROM deletion_requests dr
        LEFT JOIN admin_users au ON dr.reviewed_by_id = au.id
        WHERE dr.status != 'pending'
        ORDER BY dr.reviewed_at DESC
        LIMIT 50
    ");
    $processed->execute();
    $processed = $processed->fetchAll();
} catch (PDOException $e) { $processed = []; }

generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Deletion Requests - MovieHub</title>
    <link rel="stylesheet" href="../assets/css/style.css?v=2.3.0">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
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
                    <div><h1 class="page-title">Deletion Requests</h1><p class="page-subtitle">Review account deletion requests from admins</p></div>
                </div>
                <div class="header-actions"><span class="badge badge-warning" style="font-size:0.875rem;"><?php echo count($pending); ?> Pending</span></div>
            </div>

            <div class="content-body">
                <?php if ($success): ?><div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($success); ?></div><?php endif; ?>
                <?php if ($error): ?><div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div><?php endif; ?>

                <?php if (empty($pending)): ?>
                    <div class="card"><div class="empty-state"><i class="fas fa-user-minus"></i><h3>No Pending Requests</h3><p>No deletion requests awaiting review.</p></div></div>
                <?php else: ?>
                    <?php foreach ($pending as $req): ?>
                    <div class="card" style="margin-bottom:1rem;">
                        <div class="card-header">
                            <h3 class="card-title" style="color:var(--danger);"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($req['full_name'] ?? 'Unknown'); ?></h3>
                            <span class="text-sm text-muted">Requested: <?php echo date('M d, Y H:i', strtotime($req['created_at'])); ?></span>
                        </div>
                        <div class="card-body">
                            <p><strong>Account Type:</strong> <?php echo $req['target_table'] === 'admin_users' ? 'Admin' : 'User'; ?></p>
                            <p><strong>Username:</strong> <?php echo htmlspecialchars($req['username'] ?? ''); ?></p>
                            <p><strong>Reason:</strong> <?php echo htmlspecialchars($req['reason'] ?? 'No reason provided'); ?></p>

                            <form method="POST" action="" style="margin-top:1rem;">
                                <?php csrf_token_input(); ?>
                                <input type="hidden" name="request_id" value="<?php echo $req['id']; ?>">
                                <div class="form-group">
                                    <label>Admin Notes</label>
                                    <textarea name="admin_notes" class="form-control" rows="2" placeholder="Add notes about this decision..."></textarea>
                                </div>
                                <div class="flex gap-3">
                                    <button type="submit" name="action" value="approve" class="btn btn-danger" style="flex:1;" onclick="return confirm('Approve deletion? This will permanently delete the account and its related records from the database.');"><i class="fas fa-check"></i> Approve Deletion</button>
                                    <button type="submit" name="action" value="reject" class="btn btn-outline" style="flex:1;"><i class="fas fa-times"></i> Reject</button>
                                </div>
                            </form>
                        </div>
                    </div>
                    <?php endforeach; ?>
                <?php endif; ?>

                <?php if (!empty($processed)): ?>
                <h3 style="margin:1.5rem 0 1rem;"><i class="fas fa-history"></i> Recent Decisions</h3>
                <div class="card">
                    <div class="table-responsive">
                        <table class="table">
                            <thead><tr><th>User</th><th>Type</th><th>Status</th><th>Reviewed By</th><th>Date</th><th>Notes</th></tr></thead>
                            <tbody>
<?php foreach ($processed as $proc): ?>
                                <tr>
                                    <td><strong><?php echo htmlspecialchars($proc['full_name'] ?? 'Unknown'); ?></strong></td>
                                    <td><?php echo $proc['target_table'] === 'admin_users' ? 'Admin' : 'User'; ?></td>
                                    <td><?php echo render_status_badge($proc['status']); ?></td>
                                    <td><?php echo htmlspecialchars($proc['reviewed_by_name'] ?? 'System'); ?></td>
                                    <td><small><?php echo date('M d, Y H:i', strtotime($proc['reviewed_at'])); ?></small></td>
                                    <td><small><?php echo !empty($proc['rejection_reason']) ? htmlspecialchars($proc['rejection_reason']) : '-'; ?></small></td>
                                </tr>
<?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <div id="sidebarOverlay" class="sidebar-overlay" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('active');"></div>
</body>
</html>
