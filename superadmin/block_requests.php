<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/authorization.php';
require_once '../includes/csrf.php';

require_login();
require_role('super_admin');
require_permission('block_requests.view');

$success = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token.';
    } elseif (($_POST['admin_password'] ?? '') === '') {
        $error = 'Please enter your current password to confirm this action.';
    } elseif (!check_user_password($pdo, 'admin_users', $_SESSION['admin_id'], $_POST['admin_password'] ?? '')) {
        $error = 'Inputted password is wrong.';
    } else {
        $action = $_POST['action'] ?? '';
        $request_id = intval($_POST['request_id'] ?? 0);
        $admin_notes = trim($_POST['admin_notes'] ?? '');

        try {
            if ($action === 'approve') {
                if (!check_permission($pdo, 'admin_users', $_SESSION['admin_id'], 'block_requests.approve')) {
                    $error = 'You do not have permission to approve block requests.';
                } else {
                    $stmt = $pdo->prepare("SELECT id, target_table, target_id, target_name FROM block_requests WHERE id = ? AND status = 'pending'");
                    $stmt->execute([$request_id]);
                    $req = $stmt->fetch();
                    if (!$req) {
                        $error = 'Request not found or already processed.';
                    } else {
                        $pdo->beginTransaction();
                        try {
                            block_account($pdo, $req['target_table'], $req['target_id'], 'Blocked via approved block request');
                            $stmt = $pdo->prepare("UPDATE block_requests SET status = 'approved', reviewed_by_id = ?, reviewed_by_name = ?, rejection_reason = ?, reviewed_at = NOW() WHERE id = ?");
                            $stmt->execute([$_SESSION['admin_id'], $_SESSION['admin_full_name'] ?? '', $admin_notes, $request_id]);
                            $pdo->prepare("INSERT INTO activity_logs (admin_id, admin_username, action, target_type, target_id, target_name, reason, ip_address) VALUES (?, ?, 'block_approve', ?, ?, ?, ?, ?)")
                                ->execute([$_SESSION['admin_id'], $_SESSION['admin_username'], $req['target_table'], $req['target_id'], $req['target_name'], $admin_notes, $_SERVER['REMOTE_ADDR'] ?? '']);
                            log_audit($pdo, 'block_approve', $req['target_table'], $req['target_id'], $req['target_name'], 'Block request approved and account blocked');
                            $pdo->commit();
                            $success = 'Block request approved. The account (' . htmlspecialchars($req['target_name']) . ') has been blocked.';
                        } catch (PDOException $e) {
                            $pdo->rollBack();
                            error_log('[block_requests] ' . $e->getMessage());
                            $error = 'Failed to approve the block request.';
                        }
                    }
                }
            } elseif ($action === 'reject') {
                if (!check_permission($pdo, 'admin_users', $_SESSION['admin_id'], 'block_requests.reject')) {
                    $error = 'You do not have permission to reject block requests.';
                } else {
                    $stmt = $pdo->prepare("UPDATE block_requests SET status = 'rejected', reviewed_by_id = ?, reviewed_by_name = ?, rejection_reason = ?, reviewed_at = NOW() WHERE id = ? AND status = 'pending'");
                    $stmt->execute([$_SESSION['admin_id'], $_SESSION['admin_full_name'] ?? '', $admin_notes, $request_id]);
                    $stmt2 = $pdo->prepare("SELECT target_table, target_id, target_name FROM block_requests WHERE id = ?");
                    $stmt2->execute([$request_id]);
                    $rreq = $stmt2->fetch();
                    if ($rreq) log_audit($pdo, 'block_reject', $rreq['target_table'], $rreq['target_id'], $rreq['target_name'], 'Block request rejected');
                    $success = 'Block request rejected.';
                }
            } else {
                $error = 'Invalid action.';
            }
        } catch (PDOException $e) {
            $pdo->rollBack();
            error_log('[block_requests] ' . $e->getMessage());
            $error = 'An error occurred.';
        }
    }
}

$pending = [];
try {
    $stmt = $pdo->prepare("
        SELECT br.*,
            COALESCE(
                CASE br.target_table
                    WHEN 'users' THEN (SELECT CONCAT(first_name,' ',last_name) FROM users WHERE id = br.target_id)
                    WHEN 'admin_users' THEN (SELECT full_name FROM admin_users WHERE id = br.target_id)
                END, br.target_name) as full_name,
            CASE br.target_table
                WHEN 'users' THEN (SELECT username FROM users WHERE id = br.target_id)
                WHEN 'admin_users' THEN (SELECT username FROM admin_users WHERE id = br.target_id)
            END as username,
            brd.file_path as doc_path,
            brd.original_name as doc_original
        FROM block_requests br
        LEFT JOIN block_request_documents brd ON brd.block_request_id = br.id
        WHERE br.status = 'pending'
        ORDER BY br.created_at ASC
    ");
    $stmt->execute();
    $pending = $stmt->fetchAll();
} catch (PDOException $e) { $pending = []; }

$processed = [];
try {
    $stmt = $pdo->prepare("
        SELECT br.*,
            COALESCE(
                CASE br.target_table
                    WHEN 'users' THEN (SELECT CONCAT(first_name,' ',last_name) FROM users WHERE id = br.target_id)
                    WHEN 'admin_users' THEN (SELECT full_name FROM admin_users WHERE id = br.target_id)
                END, br.target_name) as full_name,
            au.full_name as reviewed_by_name,
            brd.file_path as doc_path,
            brd.original_name as doc_original
        FROM block_requests br
        LEFT JOIN block_request_documents brd ON brd.block_request_id = br.id
        LEFT JOIN admin_users au ON br.reviewed_by_id = au.id
        WHERE br.status != 'pending'
        ORDER BY br.reviewed_at DESC
        LIMIT 50
    ");
    $stmt->execute();
    $processed = $stmt->fetchAll();
} catch (PDOException $e) { $processed = []; }

generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Block Requests - MovieHub</title>
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
                    <div><h1 class="page-title">Block Requests</h1><p class="page-subtitle">Review account block requests submitted by admins</p></div>
                </div>
                <div class="header-actions"><span class="badge badge-warning" style="font-size:0.875rem;"><?php echo count($pending); ?> Pending</span></div>
            </div>

            <div class="content-body">
                <?php if ($success): ?><div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($success); ?></div><?php endif; ?>
                <?php if ($error): ?><div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div><?php endif; ?>

                <?php if (empty($pending)): ?>
                    <div class="card"><div class="empty-state"><i class="fas fa-ban"></i><h3>No Pending Requests</h3><p>No block requests awaiting review.</p></div></div>
                <?php else: ?>
                    <?php foreach ($pending as $req): ?>
                    <div class="card" style="margin-bottom:1rem;">
                        <div class="card-header">
                            <h3 class="card-title" style="color:var(--danger);"><i class="fas fa-ban"></i> <?php echo htmlspecialchars($req['full_name'] ?? 'Unknown'); ?></h3>
                            <span class="text-sm text-muted">Requested: <?php echo date('M d, Y H:i', strtotime($req['created_at'])); ?> by <?php echo htmlspecialchars($req['requested_by_name'] ?? 'Admin'); ?></span>
                        </div>
                        <div class="card-body">
                            <p><strong>Account Type:</strong> <?php echo $req['target_table'] === 'admin_users' ? 'Admin' : 'User'; ?></p>
                            <p><strong>Username:</strong> <?php echo htmlspecialchars($req['username'] ?? ''); ?></p>
                            <p><strong>Reason:</strong> <?php echo htmlspecialchars($req['reason'] ?? 'No reason provided'); ?></p>
                            <?php if (!empty($req['doc_path'])): ?>
                            <p><strong>Supporting Document:</strong> <a href="../assets/block_request_documents/<?php echo htmlspecialchars($req['doc_path']); ?>" target="_blank" class="btn btn-sm btn-outline" style="vertical-align:middle;"><i class="fas fa-file-download"></i> <?php echo htmlspecialchars($req['doc_original'] ?? 'View Document'); ?></a></p>
                            <?php endif; ?>

                            <form method="POST" action="" style="margin-top:1rem;" onsubmit="return confirm('Please verify this block request before proceeding.');">
                                <?php csrf_token_input(); ?>
                                <input type="hidden" name="request_id" value="<?php echo $req['id']; ?>">
                                <div class="form-group">
                                    <label>Admin Notes</label>
                                    <textarea name="admin_notes" class="form-control" rows="2" placeholder="Add notes about this decision..."></textarea>
                                </div>
                                <div class="form-group">
                                    <label>Your Password (to confirm) *</label>
                                    <input type="password" name="admin_password" class="form-control" autocomplete="off" placeholder="Enter YOUR current password to confirm" required>
                                </div>
                                <div class="flex gap-3">
                                    <button type="submit" name="action" value="approve" class="btn btn-danger" style="flex:1;"><i class="fas fa-check"></i> Approve &amp; Block</button>
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