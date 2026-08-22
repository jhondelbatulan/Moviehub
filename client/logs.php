<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/authorization.php';
require_once '../includes/csrf.php';

require_login();
require_role('user');

$filter_action = isset($_GET['action']) ? $_GET['action'] : '';
if (!in_array($filter_action, ['login', 'logout'])) { $filter_action = ''; }

$page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
$per_page = RECORDS_PER_PAGE;
$offset = ($page - 1) * $per_page;

try {
    if ($filter_action != '') {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM login_logs WHERE user_table = 'users' AND user_id = ? AND action = ?");
        $stmt->execute([$_SESSION['user_id'], $filter_action]);
    } else {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM login_logs WHERE user_table = 'users' AND user_id = ?");
        $stmt->execute([$_SESSION['user_id']]);
    }
    $total_records = (int)$stmt->fetchColumn();
} catch (PDOException $e) { $total_records = 0; }

$total_pages = max(1, (int)ceil($total_records / $per_page));
if ($page > $total_pages) { $page = $total_pages; $offset = ($page - 1) * $per_page; }

try {
    $sql = "SELECT * FROM login_logs WHERE user_table = 'users' AND user_id = ?";
    $params = [$_SESSION['user_id']];
    if ($filter_action != '') { $sql .= " AND action = ?"; $params[] = $filter_action; }
    $sql .= " ORDER BY created_at DESC LIMIT " . (int)$per_page . " OFFSET " . (int)$offset;
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $logs = $stmt->fetchAll();
} catch (PDOException $e) { $logs = []; }

try { $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$_SESSION['user_id']]); $user = $stmt->fetch(); } catch (PDOException $e) { $user = null; }

function build_log_url($p, $filter) {
    $params = [];
    if ($filter != '') { $params['action'] = $filter; }
    if ($p > 1) { $params['page'] = $p; }
    return empty($params) ? 'logs.php' : 'logs.php?' . http_build_query($params);
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Activity Logs - MovieHub</title>
    <link rel="stylesheet" href="../assets/css/style.css?v=2.3.0">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body>
    <?php require_once '../includes/navbar.php'; ?>
    <main class="mh-main">
        <div class="mh-page-head">
            <div>
                <h1 class="page-title">My Activity Logs</h1>
                <p class="page-subtitle"><?php echo $total_records; ?> record<?php echo $total_records == 1 ? '' : 's'; ?> found</p>
            </div>
            <div class="header-actions"><span class="text-sm text-muted"><i class="fas fa-calendar"></i> <?php echo date('M d, Y'); ?></span></div>
        </div>

            <div class="content-body">
                <div class="card" style="margin-bottom:1.5rem;">
                    <form method="GET" action="logs.php" class="flex items-center gap-3 flex-wrap">
                        <label for="action_filter" style="font-weight:500;"><i class="fas fa-filter"></i> Filter by Action:</label>
                        <select name="action" id="action_filter" class="form-control" style="width:auto;" onchange="this.form.submit();">
                            <option value="">All Actions</option>
                            <option value="login" <?php echo $filter_action == 'login' ? 'selected' : ''; ?>>Login</option>
                            <option value="logout" <?php echo $filter_action == 'logout' ? 'selected' : ''; ?>>Logout</option>
                        </select>
                        <button type="submit" class="btn btn-sm btn-primary"><i class="fas fa-search"></i> Apply</button>
                        <a href="logs.php" class="btn btn-sm btn-secondary"><i class="fas fa-redo"></i> Reset</a>
                        <span class="pagination-info">Showing <?php echo count($logs); ?> of <?php echo $total_records; ?> record(s)</span>
                    </form>
                </div>

                <div class="card">
<?php if (!empty($logs)): ?>
                    <div class="table-responsive">
                        <table class="table">
                            <thead><tr><th>Action</th><th>Result</th><th>IP Address</th><th>Date/Time</th></tr></thead>
                            <tbody>
<?php foreach ($logs as $log): ?>
                                <tr>
                                    <td>
                                        <?php if ($log['action'] == 'login'): ?>
                                            <span class="badge badge-info"><i class="fas fa-sign-in-alt"></i> Login</span>
                                        <?php else: ?>
                                            <span class="badge badge-secondary"><i class="fas fa-sign-out-alt"></i> Logout</span>
                                        <?php endif; ?>
                                    </td>
                                    <td><?php if ($log['status'] === 'success'): ?><span class="badge badge-success">Success</span><?php else: ?><span class="badge badge-danger"><?php echo ucfirst(htmlspecialchars($log['status'])); ?></span><?php endif; ?></td>
                                    <td><?php echo !empty($log['ip_address']) ? htmlspecialchars($log['ip_address']) : '<span class="text-muted">Unknown</span>'; ?></td>
                                    <td><small class="text-muted"><?php echo date('M d, Y h:i A', strtotime($log['created_at'])); ?></small></td>
                                </tr>
<?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
<?php else: ?>
                    <div class="empty-state"><i class="fas fa-history"></i><h3>No Activity Logs</h3><p>No <?php echo $filter_action != '' ? htmlspecialchars($filter_action) : ''; ?> activity records found for your account.</p></div>
<?php endif; ?>

<?php if ($total_pages > 1): ?>
                    <div style="display:flex;justify-content:space-between;align-items:center;padding:1rem 1.5rem;border-top:1px solid var(--border-color);flex-wrap:wrap;gap:0.5rem;">
                        <span class="pagination-info">Page <?php echo $page; ?> of <?php echo $total_pages; ?></span>
                        <div class="pagination">
<?php if ($page > 1): ?>
                            <a href="<?php echo htmlspecialchars(build_log_url($page - 1, $filter_action)); ?>" class="page-link">&laquo; Prev</a>
<?php endif; ?>
<?php for ($i = 1; $i <= $total_pages; $i++): ?>
                            <a href="<?php echo htmlspecialchars(build_log_url($i, $filter_action)); ?>" class="page-link<?php echo $i == $page ? ' active' : ''; ?>"><?php echo $i; ?></a>
<?php endfor; ?>
<?php if ($page < $total_pages): ?>
                            <a href="<?php echo htmlspecialchars(build_log_url($page + 1, $filter_action)); ?>" class="page-link">Next &raquo;</a>
<?php endif; ?>
                        </div>
                    </div>
<?php endif; ?>
                </div>
        </div>
    </main>
</body>
</html>
