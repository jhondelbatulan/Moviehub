<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/authorization.php';
require_once '../includes/csrf.php';

require_login();
require_role('super_admin');
require_permission('movies.delete');

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
                $stmt = $pdo->prepare("SELECT id, movie_id, movie_title FROM movie_deletion_requests WHERE id = ? AND status = 'pending'");
                $stmt->execute([$request_id]);
                $req = $stmt->fetch();
                if (!$req) {
                    $error = 'Request not found or already processed.';
                } else {
                    $movie_id = (int)$req['movie_id'];
                    $stmt = $pdo->prepare("SELECT COUNT(*) FROM rentals WHERE movie_id = ? AND status = 'pending'");
                    $stmt->execute([$movie_id]);
                    if ($stmt->fetchColumn() > 0) {
                        $error = 'Cannot delete movie with pending rentals. Resolve the pending rentals first.';
                    } else {
                        $pdo->beginTransaction();
                        try {
                            // Remove the movie; log the deletion either way for the trail.
                            $stmt = $pdo->prepare("DELETE FROM movies WHERE movie_id = ?");
                            $stmt->execute([$movie_id]);
                            $stmt = $pdo->prepare("UPDATE movie_deletion_requests SET status = 'approved', reviewed_by_id = ?, reviewed_by_name = ?, review_notes = ?, reviewed_at = NOW() WHERE id = ?");
                            $stmt->execute([$_SESSION['admin_id'], $_SESSION['admin_full_name'] ?? '', $admin_notes, $request_id]);
                            $pdo->prepare("INSERT INTO activity_logs (admin_id, admin_username, action, target_type, target_id, target_name, reason, ip_address) VALUES (?, ?, 'movie_delete_approve', 'movies', ?, ?, ?, ?)")
                                ->execute([$_SESSION['admin_id'], $_SESSION['admin_username'], $movie_id, $req['movie_title'], $admin_notes, $_SERVER['REMOTE_ADDR'] ?? '']);
                            log_audit($pdo, 'movie_deleted', 'movies', $movie_id, $req['movie_title'], 'Movie "' . $req['movie_title'] . '" (ID: ' . $movie_id . ') deleted via approved deletion request');
                            $pdo->commit();
                            $success = 'Deletion request approved. The movie (' . htmlspecialchars($req['movie_title']) . ') has been deleted from the catalog.';
                        } catch (PDOException $e) {
                            $pdo->rollBack();
                            error_log('[movie_deletion_requests] ' . $e->getMessage());
                            $error = 'Failed to delete the movie.';
                        }
                    }
                }
            } elseif ($action === 'reject') {
                $stmt = $pdo->prepare("UPDATE movie_deletion_requests SET status = 'rejected', reviewed_by_id = ?, reviewed_by_name = ?, review_notes = ?, reviewed_at = NOW() WHERE id = ? AND status = 'pending'");
                $stmt->execute([$_SESSION['admin_id'], $_SESSION['admin_full_name'] ?? '', $admin_notes, $request_id]);
                $stmt2 = $pdo->prepare("SELECT movie_id, movie_title FROM movie_deletion_requests WHERE id = ?");
                $stmt2->execute([$request_id]);
                $rreq = $stmt2->fetch();
                if ($rreq) log_audit($pdo, 'movie_delete_reject', 'movies', (int)$rreq['movie_id'], $rreq['movie_title'], 'Movie deletion request rejected');
                $success = 'Deletion request rejected.';
            } else {
                $error = 'Invalid action.';
            }
        } catch (PDOException $e) {
            $pdo->rollBack();
            error_log('[movie_deletion_requests] ' . $e->getMessage());
            $error = 'An error occurred.';
        }
    }
}

$pending = [];
try {
    $stmt = $pdo->prepare("
        SELECT mdr.*, m.title AS current_title, mdrd.file_path AS doc_path, mdrd.original_name AS doc_original
        FROM movie_deletion_requests mdr
        LEFT JOIN movies m ON m.movie_id = mdr.movie_id
        LEFT JOIN movie_deletion_documents mdrd ON mdrd.request_id = mdr.id
        WHERE mdr.status = 'pending'
        ORDER BY mdr.created_at ASC
    ");
    $stmt->execute();
    $pending = $stmt->fetchAll();
} catch (PDOException $e) { $pending = []; }

$processed = [];
try {
    $stmt = $pdo->prepare("
        SELECT mdr.*, m.title AS current_title, mdrd.file_path AS doc_path, mdrd.original_name AS doc_original
        FROM movie_deletion_requests mdr
        LEFT JOIN movies m ON m.movie_id = mdr.movie_id
        LEFT JOIN movie_deletion_documents mdrd ON mdrd.request_id = mdr.id
        WHERE mdr.status != 'pending'
        ORDER BY mdr.reviewed_at DESC
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
    <title>Movie Deletion Requests - MovieHub</title>
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
                    <div><h1 class="page-title">Movie Deletion Requests</h1><p class="page-subtitle">Review movie deletion requests submitted by admins</p></div>
                </div>
                <div class="header-actions"><span class="badge badge-warning" style="font-size:0.875rem;"><?php echo count($pending); ?> Pending</span></div>
            </div>

            <div class="content-body">
                <?php if ($success): ?><div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($success); ?></div><?php endif; ?>
                <?php if ($error): ?><div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div><?php endif; ?>

                <?php if (empty($pending)): ?>
                    <div class="card"><div class="empty-state"><i class="fas fa-film"></i><h3>No Pending Requests</h3><p>No movie deletion requests awaiting review.</p></div></div>
                <?php else: ?>
                    <?php foreach ($pending as $req): ?>
                    <div class="card" style="margin-bottom:1rem;">
                        <div class="card-header">
                            <h3 class="card-title" style="color:var(--danger);"><i class="fas fa-film"></i> <?php echo htmlspecialchars($req['movie_title']); ?></h3>
                            <span class="text-sm text-muted">Requested: <?php echo date('M d, Y H:i', strtotime($req['created_at'])); ?> by <?php echo htmlspecialchars($req['requested_by_name'] ?? 'Admin'); ?></span>
                        </div>
                        <div class="card-body">
                            <?php if ($req['current_title'] === null): ?>
                                <p class="text-danger"><i class="fas fa-exclamation-triangle"></i> This movie no longer exists in the catalog. You can only reject this request.</p>
                            <?php endif; ?>
                            <p><strong>Movie ID:</strong> <?php echo (int)$req['movie_id']; ?></p>
                            <p><strong>Reason:</strong> <?php echo htmlspecialchars($req['reason'] ?? 'No reason provided'); ?></p>
                            <?php if (!empty($req['doc_path'])): ?>
                            <p><strong>Supporting Document:</strong> <a href="../assets/movie_change_documents/<?php echo htmlspecialchars($req['doc_path']); ?>" target="_blank" class="btn btn-sm btn-outline" style="vertical-align:middle;"><i class="fas fa-file-download"></i> <?php echo htmlspecialchars($req['doc_original'] ?? 'View Document'); ?></a></p>
                            <?php endif; ?>

                            <form method="POST" action="" style="margin-top:1rem;" onsubmit="return confirm('Please verify this movie deletion request before proceeding.');">
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
                                    <?php if ($req['current_title'] !== null): ?>
                                    <button type="submit" name="action" value="approve" class="btn btn-danger" style="flex:1;"><i class="fas fa-check"></i> Approve &amp; Delete</button>
                                    <?php endif; ?>
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
                            <thead><tr><th>Movie</th><th>Requested By</th><th>Status</th><th>Reviewed By</th><th>Date</th><th>Notes</th></tr></thead>
                            <tbody>
<?php foreach ($processed as $proc): ?>
                                <tr>
                                    <td><strong><?php echo htmlspecialchars($proc['movie_title']); ?></strong><?php if ($proc['current_title'] === null): ?><br><small class="text-muted">(deleted from catalog)</small><?php endif; ?></td>
                                    <td><small><?php echo htmlspecialchars($proc['requested_by_name'] ?? '-'); ?></small></td>
                                    <td><?php echo render_status_badge($proc['status']); ?></td>
                                    <td><small><?php echo htmlspecialchars($proc['reviewed_by_name'] ?? 'System'); ?></small></td>
                                    <td><small><?php echo $proc['reviewed_at'] ? date('M d, Y H:i', strtotime($proc['reviewed_at'])) : '-'; ?></small></td>
                                    <td><small><?php echo !empty($proc['review_notes']) ? htmlspecialchars($proc['review_notes']) : '-'; ?></small></td>
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
