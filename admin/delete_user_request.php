<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/authorization.php';
require_once '../includes/csrf.php';

require_login();
require_role(['admin', 'super_admin']);
require_permission('users.delete');

$success = '';
$error = '';

$table = $_GET['table'] ?? $_POST['target_table'] ?? 'users';
$id = intval($_GET['id'] ?? $_POST['target_id'] ?? 0);

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token.';
    } else {
        $target_id = intval($_POST['target_id']);
        $reason = trim($_POST['reason'] ?? '');

        if (empty($reason)) {
            $error = 'Please provide a reason for the deletion request.';
        } else {
            $stmt = $pdo->prepare("SELECT CONCAT(first_name, ' ', last_name) as full_name FROM users WHERE id = ?");
            $stmt->execute([$target_id]);
            $row = $stmt->fetch();
            if ($row) {
                $stmt = $pdo->prepare("INSERT INTO deletion_requests (target_table, target_id, target_name, reason, requested_by_id, requested_by_name, status) VALUES ('users', ?, ?, ?, ?, ?, 'pending')");
                $stmt->execute([$target_id, $row['full_name'], $reason, $_SESSION['admin_id'], $_SESSION['admin_full_name']]);
                $success = 'Deletion request for <strong>' . htmlspecialchars($row['full_name']) . '</strong> has been sent to Super Admin for review.';
            } else {
                $error = 'User not found.';
            }
        }
    }
}

$user_info = null;
if ($id > 0) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$id]);
    $user_info = $stmt->fetch();
}

generate_csrf_token();
$is_superadmin = (($_SESSION['admin_role'] ?? '') === 'super_admin');
$dash_link = $is_superadmin ? '../superadmin/dashboard.php' : 'dashboard.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Request Account Deletion - MovieHub</title>
    <link rel="stylesheet" href="../assets/css/style.css?v=2.3.0">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body>
    <div class="page-wrapper">
        <aside class="sidebar" id="sidebar">
            <div class="sidebar-header"><a href="<?php echo $dash_link; ?>" class="sidebar-logo"><i class="fas fa-film"></i><span>MovieHub</span></a></div>
            <nav class="sidebar-nav">
<?php if ($is_superadmin): ?>
                <div class="sidebar-section"><div class="sidebar-section-title">Overview</div>
                    <a href="../superadmin/dashboard.php" class="sidebar-link"><i class="fas fa-tachometer-alt"></i><span>Dashboard</span></a>
                </div>
                <div class="sidebar-section"><div class="sidebar-section-title">User Management</div>
                    <a href="../superadmin/account_management.php" class="sidebar-link active"><i class="fas fa-users-cog"></i><span>Account Management</span></a>
                    <a href="../superadmin/create_account.php" class="sidebar-link"><i class="fas fa-user-plus"></i><span>Create Account</span></a>
                    <a href="registration_approval.php" class="sidebar-link"><i class="fas fa-user-check"></i><span>Registration Approvals</span></a>
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
                    <a href="manage_movies.php" class="sidebar-link"><i class="fas fa-film"></i><span>Manage Movies</span></a>
                    <a href="manage_genres.php" class="sidebar-link"><i class="fas fa-tags"></i><span>Manage Genres</span></a>
                    <a href="rental_requests.php" class="sidebar-link"><i class="fas fa-clipboard-list"></i><span>Rental Requests</span></a>
                    <a href="registration_approval.php" class="sidebar-link"><i class="fas fa-user-check"></i><span>Approvals</span></a>
                    <a href="login_logs.php" class="sidebar-link"><i class="fas fa-history"></i><span>Login Logs</span></a>
                </div>
<?php endif; ?>
                <div class="sidebar-section"><div class="sidebar-section-title">Account</div>
                    <a href="../client/logout.php" class="sidebar-link"><i class="fas fa-sign-out-alt"></i><span>Logout</span></a>
                </div>
            </nav>
            <a href="../superadmin/edit_admin.php?id=<?php echo (int)$_SESSION['admin_id']; ?>" class="sidebar-user" style="display:flex;align-items:center;gap:0.75rem;padding:0.75rem 1rem;color:inherit;text-decoration:none;transition:background 0.15s;cursor:pointer;" title="Edit my profile">
                <div class="avatar avatar-sm" style="background:var(--primary);color:white;"><?php echo strtoupper(substr($_SESSION['admin_full_name'], 0, 1)); ?></div>
                <div class="sidebar-user-info">
                    <div class="sidebar-user-name"><?php echo htmlspecialchars($_SESSION['admin_full_name']); ?></div>
                    <div class="sidebar-user-role" style="color:var(--primary);font-weight:600;"><?php echo $is_superadmin ? 'Super Admin' : ucfirst(str_replace('_', ' ', $_SESSION['admin_role'] ?? 'admin')); ?></div>
                </div>
            </a>
        </aside>

        <div class="main-content">
            <div class="top-header">
                <div class="flex items-center gap-3">
                    <button class="sidebar-toggle" onclick="document.getElementById('sidebar').classList.toggle('open');document.getElementById('sidebarOverlay').classList.toggle('active');"><i class="fas fa-bars"></i></button>
                    <div><h1 class="page-title">Request Account Deletion</h1><p class="page-subtitle">Submit a deletion request to Super Admin for review</p></div>
                </div>
            </div>

            <div class="content-body">
                <?php if ($success): ?>
                    <div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo $success; ?></div>
                    <a href="dashboard.php" class="btn btn-primary"><i class="fas fa-arrow-left"></i> Back to Dashboard</a>
                <?php elseif ($error): ?>
                    <div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div>
                    <a href="dashboard.php" class="btn btn-outline"><i class="fas fa-arrow-left"></i> Back to Dashboard</a>
                <?php elseif (!$user_info): ?>
                    <div class="card"><div class="empty-state"><i class="fas fa-user-slash"></i><h3>User Not Found</h3><p>The requested user account could not be found.</p><a href="dashboard.php" class="btn btn-primary">Back to Dashboard</a></div></div>
                <?php else: ?>
                    <div class="card" style="margin-bottom:1.5rem;">
                        <div class="card-header"><h3 class="card-title"><i class="fas fa-user"></i> Complete User Information</h3></div>
                        <div class="card-body">
                            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:0.75rem;">
                                <div><strong>Full Name:</strong> <?php echo htmlspecialchars(trim($user_info['first_name'].' '.$user_info['middle_initial'].' '.$user_info['last_name']).($user_info['extension_name']?' '.$user_info['extension_name']:'')); ?></div>
                                <div><strong>Username:</strong> <?php echo htmlspecialchars($user_info['username']); ?></div>
                                <div><strong>Email:</strong> <?php echo htmlspecialchars($user_info['email']); ?></div>
                                <div><strong>ID Number:</strong> <?php echo htmlspecialchars($user_info['id_number']); ?></div>
                                <div><strong>Employee ID:</strong> <?php echo htmlspecialchars($user_info['employee_id']); ?></div>
                                <div><strong>Sex:</strong> <?php echo htmlspecialchars($user_info['sex']); ?></div>
                                <div><strong>Birthdate:</strong> <?php echo htmlspecialchars($user_info['birthdate']); ?></div>
                                <div><strong>Contact:</strong> <?php echo htmlspecialchars($user_info['contact_number']); ?></div>
                                <div style="grid-column:1/-1;"><strong>Address:</strong> <?php echo htmlspecialchars(implode(', ', array_filter([$user_info['address_street'],$user_info['address_barangay'],$user_info['address_city'],$user_info['address_province'],$user_info['address_country'],$user_info['zip_code']]))); ?></div>
                                <div><strong>Role:</strong> <?php echo render_role_badge($user_info['role'] ?? 'user'); ?></div>
                                <div><strong>Status:</strong> <?php echo render_status_badge($user_info['account_status']); ?></div>
                            </div>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header"><h3 class="card-title" style="color:var(--danger);"><i class="fas fa-exclamation-triangle"></i> Reason for Deletion</h3></div>
                        <div class="card-body">
                            <form method="POST" action="">
                                <?php csrf_token_input(); ?>
                                <input type="hidden" name="target_table" value="users">
                                <input type="hidden" name="target_id" value="<?php echo $id; ?>">
                                <div class="form-group">
                                    <label>Why should this account be deleted? *</label>
                                    <textarea name="reason" class="form-control" rows="4" required placeholder="Provide a detailed reason for the deletion request..."></textarea>
                                </div>
                                <p style="font-size:0.8125rem;color:var(--text-light);margin-bottom:1rem;"><i class="fas fa-info-circle"></i> This request will be sent to the Super Administrator for review. The account will not be deleted until the Super Admin approves the request.</p>
                                <div class="flex gap-3">
                                    <a href="dashboard.php" class="btn btn-outline" style="flex:1;"><i class="fas fa-times"></i> Cancel</a>
                                    <button type="submit" class="btn btn-danger" style="flex:1;" onclick="return confirm('Are you sure you want to submit this deletion request?');"><i class="fas fa-paper-plane"></i> Send Deletion Request</button>
                                </div>
                            </form>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <div id="sidebarOverlay" class="sidebar-overlay" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('active');"></div>
</body>
</html>
