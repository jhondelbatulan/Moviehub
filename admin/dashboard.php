<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/authorization.php';
require_once '../includes/csrf.php';

require_login();
require_role(['admin', 'super_admin']);
require_permission('dashboard.view');

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
                $success = 'Rental request approved successfully!';
            } elseif ($action == 'deny') {
                $stmt = $pdo->prepare("UPDATE rentals SET status = 'denied', admin_notes = ? WHERE rental_id = ?");
                $stmt->execute([$admin_notes, $request_id]);
                $success = 'Rental request denied.';
            }
        } catch (PDOException $e) { $error = 'Error updating request. Please try again.'; }
    }
}

try {
    $stmt = $pdo->query("SELECT r.*, u.username, u.first_name, u.last_name, u.email, u.contact_number, m.title, g.name AS genre, m.rental_price AS daily_price FROM rentals r JOIN users u ON r.user_id = u.id JOIN movies m ON r.movie_id = m.movie_id LEFT JOIN genres g ON m.genre_id = g.id ORDER BY r.created_at DESC");
    $rental_requests = $stmt->fetchAll();
} catch (PDOException $e) { $rental_requests = []; }

try {
    $total_movies = $pdo->query("SELECT COUNT(*) FROM movies")->fetchColumn();
    $available_movies = $pdo->query("SELECT COUNT(*) FROM movies WHERE status = 'available'")->fetchColumn();
    $pending_requests = $pdo->query("SELECT COUNT(*) FROM rentals WHERE status = 'pending'")->fetchColumn();
    $total_users = $pdo->query("SELECT COUNT(*) FROM users WHERE is_deleted = 0")->fetchColumn();
    $pending_approvals = $pdo->query("SELECT COUNT(*) FROM registration_approvals WHERE status = 'pending'")->fetchColumn();
    $active_rentals = $pdo->query("SELECT COUNT(*) FROM rentals WHERE status = 'approved' AND returned_at IS NULL")->fetchColumn();
    $completed_rentals = $pdo->query("SELECT COUNT(*) FROM rentals WHERE returned_at IS NOT NULL")->fetchColumn();
    $total_revenue = $pdo->query("SELECT COALESCE(SUM(rental_price), 0) FROM rentals WHERE status = 'approved'")->fetchColumn();
    $total_genres = $pdo->query("SELECT COUNT(*) FROM genres")->fetchColumn();
} catch (PDOException $e) {
    $total_movies = $available_movies = $pending_requests = $total_users = $pending_approvals = 0;
    $active_rentals = $completed_rentals = $total_revenue = $total_genres = 0;
}

try {
    $recent_movies = $pdo->query("SELECT m.movie_id, m.title, m.poster, m.release_year, m.rental_price, m.created_at, g.name AS genre FROM movies m LEFT JOIN genres g ON m.genre_id = g.id ORDER BY m.created_at DESC LIMIT 6")->fetchAll();
} catch (PDOException $e) { $recent_movies = []; }

generate_csrf_token();

auto_inactivate_accounts($pdo);

$show_edit_profile_notice = !empty($_SESSION['show_edit_profile_notice']);
if ($show_edit_profile_notice) {
    unset($_SESSION['show_edit_profile_notice']);
}

try { $stmt = $pdo->prepare("SELECT * FROM admin_users WHERE id = ?"); $stmt->execute([$_SESSION['admin_id']]); $admin_row = $stmt->fetch(); } catch (PDOException $e) { $admin_row = null; }
$admin_row = $admin_row ?: [];
$profile_complete = is_profile_complete($admin_row, true);
$cp_first = $admin_row['first_name'] ?? '';
$cp_last = $admin_row['last_name'] ?? '';
if (($cp_first === '' || $cp_last === '') && !empty($admin_row['full_name'])) {
    $parts = preg_split('/\s+/', trim($admin_row['full_name']), 2);
    if ($cp_first === '') $cp_first = $parts[0] ?? '';
    if ($cp_last === '') $cp_last = $parts[1] ?? '';
}
$cp_middle = $admin_row['middle_initial'] ?? '';
$cp_sex = $admin_row['sex'] ?? '';
$cp_birthdate = $admin_row['birthdate'] ?? '';
$cp_email = $admin_row['email'] ?? '';
$cp_contact = $admin_row['contact_number'] ?? '';
$cp_address = $admin_row['address'] ?? '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - MovieHub</title>
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
                    <div>
                        <h1 class="page-title">Admin Dashboard</h1>
                        <p class="page-subtitle">Welcome back, <?php echo htmlspecialchars($_SESSION['admin_full_name']); ?></p>
                    </div>
                </div>
                <div class="header-actions" style="display:flex;align-items:center;gap:0.5rem;">
                    <a href="manage_movies.php" class="btn btn-sm btn-outline"><i class="fas fa-plus"></i> Add Movie</a>
                    <a href="rental_requests.php?status=pending" class="btn btn-sm btn-primary"><i class="fas fa-clipboard-check"></i> Process Rentals</a>
                    <span class="text-sm text-muted"><i class="fas fa-calendar"></i> <?php echo date('M d, Y'); ?></span>
                    <a href="../client/logout.php" class="btn btn-sm btn-outline"><i class="fas fa-sign-out-alt"></i> Logout</a>
                </div>
            </div>

            <div class="content-body">
                <?php if ($success): ?><div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($success); ?></div><?php endif; ?>
                <?php if ($error): ?><div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div><?php endif; ?>

                <div class="dashboard-grid">
                    <div class="stat-card"><div class="stat-card-icon purple"><i class="fas fa-film"></i></div><div class="stat-card-value"><?php echo $total_movies; ?></div><div class="stat-card-label">Total Movies</div></div>
                    <div class="stat-card"><div class="stat-card-icon teal"><i class="fas fa-users"></i></div><div class="stat-card-value"><?php echo $total_users; ?></div><div class="stat-card-label">Total Users</div></div>
                    <div class="stat-card"><div class="stat-card-icon blue"><i class="fas fa-play-circle"></i></div><div class="stat-card-value"><?php echo $active_rentals; ?></div><div class="stat-card-label">Active Rentals</div></div>
                    <div class="stat-card"><div class="stat-card-icon green"><i class="fas fa-check-double"></i></div><div class="stat-card-value"><?php echo $completed_rentals; ?></div><div class="stat-card-label">Completed Rentals</div></div>
                    <div class="stat-card"><div class="stat-card-icon amber"><i class="fas fa-coins"></i></div><div class="stat-card-value"><?php echo CURRENCY_SYMBOL . number_format((float)$total_revenue, 2); ?></div><div class="stat-card-label">Total Revenue (Approved)</div></div>
                    <div class="stat-card"><div class="stat-card-icon red"><i class="fas fa-clock"></i></div><div class="stat-card-value"><?php echo $pending_requests; ?></div><div class="stat-card-label">Pending Requests</div></div>
                    <div class="stat-card"><div class="stat-card-icon green"><i class="fas fa-check-circle"></i></div><div class="stat-card-value"><?php echo $available_movies; ?></div><div class="stat-card-label">Available Movies</div></div>
                    <div class="stat-card"><div class="stat-card-icon purple"><i class="fas fa-tags"></i></div><div class="stat-card-value"><?php echo $total_genres; ?></div><div class="stat-card-label">Genres</div></div>
                </div>

                <?php if ($pending_approvals > 0): ?>
                <div class="alert alert-warning" style="margin-bottom:1.5rem;">
                    <i class="fas fa-user-clock"></i> There are <strong><?php echo $pending_approvals; ?></strong> pending registration(s) awaiting approval.
                    <a href="registration_approval.php" class="btn btn-sm btn-warning" style="margin-left:0.5rem;">Review Now</a>
                </div>
                <?php endif; ?>

                <div class="card" style="margin-bottom:1.5rem;">
                    <div class="card-header">
                        <h3 class="card-title"><i class="fas fa-plus-circle"></i> Recently Added Movies</h3>
                        <a href="manage_movies.php" class="btn btn-sm btn-outline">Manage Movies</a>
                    </div>
                    <div class="card-body">
                        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:1rem;">
<?php foreach ($recent_movies as $movie): ?>
                            <div style="border:1px solid var(--border);border-radius:var(--radius-lg);overflow:hidden;background:var(--background);">
                                <div style="height:120px;background:var(--surface);display:flex;align-items:center;justify-content:center;">
                                    <?php if (!empty($movie['poster'])): ?>
                                        <img src="<?php echo htmlspecialchars($movie['poster']); ?>" alt="<?php echo htmlspecialchars($movie['title']); ?>" style="width:100%;height:100%;object-fit:cover;">
                                    <?php else: ?>
                                        <i class="fas fa-film" style="font-size:2rem;color:var(--muted);"></i>
                                    <?php endif; ?>
                                </div>
                                <div style="padding:0.625rem;">
                                    <div style="font-weight:600;font-size:0.8125rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="<?php echo htmlspecialchars($movie['title']); ?>"><?php echo htmlspecialchars($movie['title']); ?></div>
                                    <div class="text-sm text-muted"><?php echo htmlspecialchars($movie['genre'] ?? ''); ?><?php echo $movie['release_year'] ? ' · ' . (int)$movie['release_year'] : ''; ?></div>
                                    <div class="flex items-center justify-between" style="margin-top:0.375rem;">
                                        <span style="font-weight:700;font-size:0.8125rem;color:var(--primary);"><?php echo CURRENCY_SYMBOL . number_format((float)$movie['rental_price'], 2); ?></span>
                                        <span class="text-xs text-muted" title="Added <?php echo date('M d, Y', strtotime($movie['created_at'])); ?>"><?php echo date('M d', strtotime($movie['created_at'])); ?></span>
                                    </div>
                                </div>
                            </div>
<?php endforeach; ?>
<?php if (empty($recent_movies)): ?>
                            <div class="empty-state" style="grid-column:1/-1;"><i class="fas fa-film"></i><p>No movies in the library yet.</p></div>
<?php endif; ?>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title"><i class="fas fa-clipboard-list"></i> Recent Rentals</h3>
                        <a href="rental_requests.php" class="btn btn-sm btn-outline">View All</a>
                    </div>
                    <div class="table-responsive">
                        <table class="table">
                            <thead><tr><th>User</th><th>Movie</th><th>Date</th><th>Amount</th><th>Status</th><th>Actions</th></tr></thead>
                            <tbody>
<?php foreach (array_slice($rental_requests, 0, 10) as $request): ?>
                                <tr>
                                    <td><strong><?php echo htmlspecialchars($request['first_name'].' '.$request['last_name']); ?></strong><br><small class="text-muted"><?php echo htmlspecialchars($request['email']); ?></small></td>
                                    <td><strong><?php echo htmlspecialchars($request['title']); ?></strong><br><small class="text-muted"><?php echo htmlspecialchars($request['genre'] ?? ''); ?></small></td>
                                    <td><?php echo date('M d, Y', strtotime($request['rental_date'])); ?></td>
                                    <td><strong><?php echo CURRENCY_SYMBOL.number_format($request['rental_price'],2); ?></strong></td>
                                    <td><span class="status-badge status-<?php echo $request['status']; ?>"><?php echo ucfirst($request['status']); ?></span></td>
                                    <td>
                                        <?php if ($request['status'] == 'pending'): ?>
                                            <div class="table-actions">
                                                <button class="btn btn-sm btn-success" onclick="openActionModal(<?php echo $request['rental_id']; ?>,'approve')"><i class="fas fa-check"></i></button>
                                                <button class="btn btn-sm btn-danger" onclick="openActionModal(<?php echo $request['rental_id']; ?>,'deny')"><i class="fas fa-times"></i></button>
                                            </div>
                                        <?php else: ?>
                                            <span class="text-sm text-muted">Processed</span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
<?php endforeach; ?>
<?php if (empty($rental_requests)): ?>
                                <tr><td colspan="6" class="text-center text-muted" style="padding:2rem;">No rental requests found.</td></tr>
<?php endif; ?>
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
            <div class="form-group"><label for="admin_notes">Admin Notes</label><textarea id="admin_notes" name="admin_notes" class="form-control" rows="3" placeholder="Add any notes about this decision..."></textarea></div>
            <button type="submit" class="btn" id="modalSubmitBtn" style="width:100%;"><i class="fas fa-check"></i> Confirm</button>
        </form>
    </div></div></div>

    <div id="sidebarOverlay" class="sidebar-overlay" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('active');"></div>
    <script>
        function openActionModal(requestId, action) {
            document.getElementById('modal_request_id').value = requestId;
            document.getElementById('modal_action').value = action;
            document.getElementById('actionModal').style.display = 'flex';
            var t = document.getElementById('modalTitle'), b = document.getElementById('modalSubmitBtn');
            if (action === 'approve') { t.textContent = 'Approve Rental Request'; b.className = 'btn btn-success'; b.innerHTML = '<i class="fas fa-check"></i> Approve Request'; }
            else { t.textContent = 'Deny Rental Request'; b.className = 'btn btn-danger'; b.innerHTML = '<i class="fas fa-times"></i> Deny Request'; }
        }
        function closeActionModal() { document.getElementById('actionModal').style.display = 'none'; }
        window.onclick = function(e) { if (e.target == document.getElementById('actionModal')) closeActionModal(); };
    </script>

    <?php if ($show_edit_profile_notice): ?>
    <div id="editProfileModal" class="modal" style="display: flex;">
        <div class="modal-content" style="max-width:480px;">
            <div class="modal-header">
                <h3 class="modal-title"><i class="fas fa-user-edit" style="margin-right:0.5rem;"></i> Update Your Account</h3>
                <span class="close" onclick="document.getElementById('editProfileModal').style.display='none'">&times;</span>
            </div>
            <div class="modal-body">
                <p>Welcome! To keep your account secure and up to date, please take a moment to review and update your personal information, including your profile details and security questions.</p>
                <div style="display:flex;gap:0.625rem;justify-content:flex-end;margin-top:1.25rem;">
                    <button class="btn btn-outline" onclick="document.getElementById('editProfileModal').style.display='none'">Later</button>
                    <a href="../superadmin/edit_admin.php?id=<?php echo (int)$_SESSION['admin_id']; ?>" class="btn btn-primary"><i class="fas fa-user-cog"></i> Edit My Details</a>
                </div>
            </div>
        </div>
    </div>
    <script>document.getElementById('editProfileModal').addEventListener('click', function(e){ if(e.target === this) this.style.display='none'; });</script>
    <?php endif; ?>

    <?php if (!$profile_complete): ?>
        <?php $cp_ajax = '../ajax/complete_profile.php'; $cp_is_admin = true; include __DIR__ . '/../includes/profile_completion_modal.php'; ?>
    <?php endif; ?>
</body>
</html>
