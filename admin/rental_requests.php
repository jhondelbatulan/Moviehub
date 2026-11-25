<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/authorization.php';
require_once '../includes/csrf.php';

require_login();
require_role(['admin', 'super_admin']);
require_permission('rentals.view');

$success = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action'])) {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token. Please try again.';
    } else {
        $request_id = (int)$_POST['request_id'];
        $action = $_POST['action'];
        $admin_notes = trim($_POST['admin_notes'] ?? '');
        try {
            if ($action == 'approve') {
                $stmt = $pdo->prepare("UPDATE rentals SET status = 'approved', admin_notes = ? WHERE rental_id = ?");
                $stmt->execute([$admin_notes, $request_id]);
                $pdo->prepare("UPDATE movies m JOIN rentals r ON r.movie_id = m.movie_id SET m.status = 'rented' WHERE r.rental_id = ? AND m.status = 'available'")->execute([$request_id]);
                $success = 'Rental request approved!';
            } elseif ($action == 'deny') {
                $stmt = $pdo->prepare("UPDATE rentals SET status = 'denied', admin_notes = ? WHERE rental_id = ?");
                $stmt->execute([$admin_notes, $request_id]);
                $success = 'Rental request denied.';
            } elseif ($action == 'return') {
                $stmt = $pdo->prepare("UPDATE rentals SET returned_at = NOW() WHERE rental_id = ? AND status = 'approved' AND returned_at IS NULL");
                $stmt->execute([$request_id]);
                if ($stmt->rowCount() > 0) {
                    $pdo->prepare("UPDATE movies m JOIN rentals r ON r.movie_id = m.movie_id SET m.status = 'available' WHERE r.rental_id = ?")->execute([$request_id]);
                    $success = 'Movie marked as returned.';
                } else {
                    $error = 'Only active approved rentals can be marked as returned.';
                }
            }
        } catch (PDOException $e) { $error = 'Error updating request.'; }
    }
}

$status_filter = isset($_GET['status']) ? $_GET['status'] : '';
$search = isset($_GET['search']) ? trim($_GET['search']) : '';

$where_conditions = [];
$params = [];
if ($status_filter) { $where_conditions[] = "r.status = ?"; $params[] = $status_filter; }
if ($search) {
    $where_conditions[] = "(CONCAT(u.first_name, ' ', u.last_name) LIKE ? OR u.email LIKE ? OR m.title LIKE ?)";
    $sp = "%$search%"; $params[] = $sp; $params[] = $sp; $params[] = $sp;
}
$where_clause = !empty($where_conditions) ? 'WHERE ' . implode(' AND ', $where_conditions) : '';

try {
    $stmt = $pdo->prepare("SELECT r.*, u.first_name, u.last_name, u.email, u.contact_number, u.profile_picture, m.title, g.name AS genre, m.rental_price AS daily_price FROM rentals r JOIN users u ON r.user_id = u.id JOIN movies m ON r.movie_id = m.movie_id LEFT JOIN genres g ON m.genre_id = g.id $where_clause ORDER BY r.created_at DESC");
    $stmt->execute($params);
    $rental_requests = $stmt->fetchAll();
} catch (PDOException $e) { $rental_requests = []; }

try {
    $total_requests = $pdo->query("SELECT COUNT(*) FROM rentals")->fetchColumn();
    $pending_requests = $pdo->query("SELECT COUNT(*) FROM rentals WHERE status = 'pending'")->fetchColumn();
    $approved_requests = $pdo->query("SELECT COUNT(*) FROM rentals WHERE status = 'approved'")->fetchColumn();
    $denied_requests = $pdo->query("SELECT COUNT(*) FROM rentals WHERE status = 'denied'")->fetchColumn();
} catch (PDOException $e) { $total_requests = $pending_requests = $approved_requests = $denied_requests = 0; }

generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rental Requests - MovieHub</title>
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
            <a href="../superadmin/edit_admin.php?id=<?php echo (int)$_SESSION['admin_id']; ?>" class="sidebar-user" style="display:flex;align-items:center;gap:0.75rem;padding:0.75rem 1rem;color:inherit;text-decoration:none;transition:background 0.15s;cursor:pointer;" title="Edit my profile">
                <div class="avatar avatar-sm"><?php echo strtoupper(substr($_SESSION['admin_full_name'], 0, 1)); ?></div>
                <div class="sidebar-user-info">
                    <div class="sidebar-user-name"><?php echo htmlspecialchars($_SESSION['admin_full_name']); ?></div>
                    <div class="sidebar-user-role"><?php echo ucfirst(str_replace('_', ' ', $_SESSION['admin_role'] ?? 'admin')); ?></div>
                </div>
            </a>
        </aside>

        <div class="main-content">
            <div class="top-header">
                <div class="flex items-center gap-3">
                    <button class="sidebar-toggle" onclick="document.getElementById('sidebar').classList.toggle('open');document.getElementById('sidebarOverlay').classList.toggle('active');"><i class="fas fa-bars"></i></button>
                    <div><h1 class="page-title">Rental Requests</h1><p class="page-subtitle">Manage and process rental requests</p></div>
                </div>
            </div>

            <div class="content-body">
                <?php if ($success): ?><div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($success); ?></div><?php endif; ?>
                <?php if ($error): ?><div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div><?php endif; ?>

                <div class="grid grid-4" style="margin-bottom:1.5rem;">
                    <div class="stat-card"><div class="stat-card-icon purple"><i class="fas fa-clipboard-list"></i></div><div class="stat-card-value"><?php echo $total_requests; ?></div><div class="stat-card-label">Total Requests</div></div>
                    <div class="stat-card"><div class="stat-card-icon amber"><i class="fas fa-clock"></i></div><div class="stat-card-value"><?php echo $pending_requests; ?></div><div class="stat-card-label">Pending</div></div>
                    <div class="stat-card"><div class="stat-card-icon green"><i class="fas fa-check-circle"></i></div><div class="stat-card-value"><?php echo $approved_requests; ?></div><div class="stat-card-label">Approved</div></div>
                    <div class="stat-card"><div class="stat-card-icon red"><i class="fas fa-times-circle"></i></div><div class="stat-card-value"><?php echo $denied_requests; ?></div><div class="stat-card-label">Denied</div></div>
                </div>

                <div class="card" style="margin-bottom:1.5rem;">
                    <div class="card-body" style="padding:1rem 1.5rem;">
                        <form method="GET" action="" class="flex items-center gap-3" style="flex-wrap:wrap;">
                            <div class="form-group" style="flex:1;min-width:200px;margin-bottom:0;"><input type="text" name="search" class="form-control" placeholder="Search by name, email, or movie..." value="<?php echo htmlspecialchars($search); ?>"></div>
                            <div class="form-group" style="flex:0 0 150px;margin-bottom:0;"><select name="status" class="form-control"><option value="">All Status</option><option value="pending" <?php echo $status_filter=='pending'?'selected':''; ?>>Pending</option><option value="approved" <?php echo $status_filter=='approved'?'selected':''; ?>>Approved</option><option value="denied" <?php echo $status_filter=='denied'?'selected':''; ?>>Denied</option></select></div>
                            <button type="submit" class="btn btn-primary btn-sm"><i class="fas fa-search"></i> Filter</button>
                            <a href="rental_requests.php" class="btn btn-outline btn-sm"><i class="fas fa-times"></i> Clear</a>
                        </form>
                    </div>
                </div>

                <div class="card">
                    <div class="table-responsive">
                        <table class="table">
                            <thead><tr><th>#</th><th>User</th><th>Movie</th><th>Rental Date</th><th>Due / Returned</th><th>Amount</th><th>Status</th><th>Notes</th><th>Actions</th></tr></thead>
                            <tbody>
<?php foreach ($rental_requests as $request): ?>
                                <tr>
                                    <td><strong>#<?php echo $request['rental_id']; ?></strong></td>
                                    <td>
                                        <div class="flex items-center gap-2">
                                            <?php if (!empty($request['profile_picture'])): ?><img src="../uploads/profile_pictures/<?php echo htmlspecialchars($request['profile_picture']); ?>" style="width:32px;height:32px;border-radius:50%;object-fit:cover;"><?php endif; ?>
                                            <div><strong><?php echo htmlspecialchars($request['first_name'].' '.$request['last_name']); ?></strong><br><small class="text-muted"><?php echo htmlspecialchars($request['email']); ?></small></div>
                                        </div>
                                    </td>
                                    <td><strong><?php echo htmlspecialchars($request['title']); ?></strong><br><small class="text-muted"><?php echo htmlspecialchars($request['genre'] ?? ''); ?></small></td>
                                    <td><?php echo date('M d, Y', strtotime($request['rental_date'])); ?></td>
                                    <td><?php if (!empty($request['returned_at'])): ?><span class="status-badge status-approved"><i class="fas fa-undo"></i> <?php echo date('M d, Y', strtotime($request['returned_at'])); ?></span><?php elseif (!empty($request['due_date'])): ?><?php echo date('M d, Y', strtotime($request['due_date'])); ?><?php else: ?>—<?php endif; ?></td>
                                    <td><strong><?php echo CURRENCY_SYMBOL.number_format($request['rental_price'],2); ?></strong></td>
                                    <td><span class="status-badge status-<?php echo $request['status']; ?>"><?php echo ucfirst($request['status']); ?></span></td>
                                    <td><small><?php echo !empty($request['admin_notes']) ? htmlspecialchars($request['admin_notes']) : '<span class="text-muted">No notes</span>'; ?></small></td>
                                    <td><?php if ($request['status']=='pending'): ?><div class="table-actions">
                                        <button class="btn btn-sm btn-success" onclick="openActionModal(<?php echo $request['rental_id']; ?>,'approve')"><i class="fas fa-check"></i></button>
                                        <button class="btn btn-sm btn-danger" onclick="openActionModal(<?php echo $request['rental_id']; ?>,'deny')"><i class="fas fa-times"></i></button>
                                    </div><?php elseif ($request['status']=='approved' && empty($request['returned_at'])): ?><div class="table-actions">
                                        <button class="btn btn-sm btn-outline" title="Mark Returned" onclick="openActionModal(<?php echo $request['rental_id']; ?>,'return')"><i class="fas fa-undo"></i></button>
                                    </div><?php else: ?><span class="text-sm text-muted">Processed</span><?php endif; ?></td>
                                </tr>
<?php endforeach; ?>
<?php if (empty($rental_requests)): ?><tr><td colspan="9" class="text-center text-muted" style="padding:2rem;">No rental requests found.</td></tr><?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div id="actionModal" class="modal"><div class="modal-content"><div class="modal-header"><h3 class="modal-title" id="modalTitle">Process Request</h3><span class="close" onclick="closeActionModal()">&times;</span></div><div class="modal-body">
        <form method="POST" action="">
            <?php csrf_token_input(); ?>
            <input type="hidden" id="modal_request_id" name="request_id">
            <input type="hidden" id="modal_action" name="action">
            <div class="form-group"><label for="admin_notes">Admin Notes</label><textarea id="admin_notes" name="admin_notes" class="form-control" rows="3" placeholder="Add notes..."></textarea></div>
            <button type="submit" class="btn" id="modalSubmitBtn" style="width:100%;"><i class="fas fa-check"></i> Confirm</button>
        </form>
    </div></div></div>
    <div id="sidebarOverlay" class="sidebar-overlay" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('active');"></div>
    <script>
        function openActionModal(id, action) {
            document.getElementById('modal_request_id').value = id;
            document.getElementById('modal_action').value = action;
            document.getElementById('actionModal').style.display = 'flex';
            var t = document.getElementById('modalTitle'), b = document.getElementById('modalSubmitBtn');
            if (action === 'approve') { t.textContent = 'Approve Request'; b.className = 'btn btn-success'; b.innerHTML = '<i class="fas fa-check"></i> Approve'; }
            else { t.textContent = 'Deny Request'; b.className = 'btn btn-danger'; b.innerHTML = '<i class="fas fa-times"></i> Deny'; }
        }
        function closeActionModal() { document.getElementById('actionModal').style.display = 'none'; }
        window.onclick = function(e) { if (e.target == document.getElementById('actionModal')) closeActionModal(); };
    </script>
</body>
</html>
