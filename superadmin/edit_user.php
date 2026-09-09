<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/authorization.php';
require_once '../includes/csrf.php';

require_login();
require_role('super_admin');

$user_id = intval($_GET['id'] ?? 0);
$error = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if ($user_id <= 0) {
        $error = 'Invalid user ID.';
    } elseif (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token.';
    } else {
        $first_name = trim($_POST['first_name'] ?? '');
        $middle_initial = strtoupper(trim($_POST['middle_initial'] ?? ''));
        $last_name = trim($_POST['last_name'] ?? '');
        $extension_name = trim($_POST['extension_name'] ?? '');
        $sex = $_POST['sex'] ?? '';
        $birthdate = trim($_POST['birthdate'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $contact_number = trim($_POST['contact_number'] ?? '');
        $address_street = trim($_POST['address_street'] ?? '');
        $address_barangay = trim($_POST['address_barangay'] ?? '');
        $address_city = trim($_POST['address_city'] ?? '');
        $address_province = trim($_POST['address_province'] ?? '');
        $address_country = trim($_POST['address_country'] ?? '');
        $zip_code = trim($_POST['zip_code'] ?? '');
        $role = $_POST['role'] ?? '';
        $account_status = $_POST['account_status'] ?? '';

        if ($first_name === '' || $last_name === '' || $email === '' || $birthdate === '' || $contact_number === '') {
            $error = 'Please fill in all required fields.';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = 'Invalid email address.';
        } elseif (!in_array($sex, ['Male', 'Female', 'Prefer not to say'], true)) {
            $error = 'Invalid sex value.';
        } elseif (!in_array($role, ['user', 'admin', 'super_admin'], true)) {
            $error = 'Invalid role.';
        } elseif (!in_array($account_status, ['approved', 'blocked', 'pending', 'rejected', 'inactive'], true)) {
            $error = 'Invalid account status.';
        } else {
            try {
                $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ? AND id != ?");
                $stmt->execute([$email, $user_id]);
                if ($stmt->fetch()) {
                    $error = 'That email address is already used by another account.';
                } else {
                    $stmt = $pdo->prepare("UPDATE users SET first_name = ?, middle_initial = ?, last_name = ?, extension_name = ?, sex = ?, birthdate = ?, email = ?, contact_number = ?, address_street = ?, address_barangay = ?, address_city = ?, address_province = ?, address_country = ?, zip_code = ?, role = ?, account_status = ? WHERE id = ?");
                    $stmt->execute([
                        $first_name,
                        $middle_initial !== '' ? $middle_initial : null,
                        $last_name,
                        $extension_name !== '' ? $extension_name : null,
                        $sex,
                        $birthdate,
                        $email,
                        $contact_number,
                        $address_street !== '' ? $address_street : null,
                        $address_barangay !== '' ? $address_barangay : null,
                        $address_city !== '' ? $address_city : null,
                        $address_province !== '' ? $address_province : null,
                        $address_country !== '' ? $address_country : null,
                        $zip_code !== '' ? $zip_code : null,
                        $role,
                        $account_status,
                        $user_id
                    ]);
                    redirect('edit_user.php?id=' . $user_id . '&updated=1');
                }
            } catch (PDOException $e) {
                error_log('[edit_user] ' . $e->getMessage());
                $error = 'Failed to update user account.';
            }
        }
    }
}

$user = null;
if ($user_id > 0) {
    try {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ? AND is_deleted = 0");
        $stmt->execute([$user_id]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$user) {
            $error = 'User not found.';
        }
    } catch (PDOException $e) {
        error_log('[edit_user] ' . $e->getMessage());
        $error = 'Failed to load user account.';
    }
} else {
    $error = 'No user ID specified.';
}

$updated = isset($_GET['updated']);
generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit User - MovieHub</title>
    <link rel="stylesheet" href="../assets/css/style.css?v=2.3.0">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
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
                    <a href="account_management.php" class="sidebar-link active"><i class="fas fa-users-cog"></i><span>Account Management</span></a>
                    <a href="create_account.php" class="sidebar-link"><i class="fas fa-user-plus"></i><span>Create Account</span></a>
                    <a href="privilege_management.php" class="sidebar-link"><i class="fas fa-shield-alt"></i><span>Privileges</span></a>
                    <a href="../admin/registration_approval.php" class="sidebar-link"><i class="fas fa-user-check"></i><span>Registration Approvals</span></a>
                    <a href="deletion_requests.php" class="sidebar-link"><i class="fas fa-user-minus"></i><span>Deletion Requests</span></a>
                </div>
                <div class="sidebar-section"><div class="sidebar-section-title">Activity</div>
                    <a href="../admin/login_logs.php" class="sidebar-link"><i class="fas fa-history"></i><span>Login Logs</span></a>
                </div>
                <div class="sidebar-section"><div class="sidebar-section-title">Account</div>
                    <a href="../client/logout.php" class="sidebar-link"><i class="fas fa-sign-out-alt"></i><span>Logout</span></a>
                </div>
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
                    <div><h1 class="page-title">Edit User</h1><p class="page-subtitle"><?php echo $user ? 'Update details for ' . htmlspecialchars($user['first_name'] . ' ' . $user['last_name']) : 'Update user account details'; ?></p></div>
                </div>
            </div>

            <div class="content-body">
                <?php if ($updated): ?><div class="alert alert-success"><i class="fas fa-check-circle"></i> User account updated successfully.</div><?php endif; ?>
                <?php if ($error): ?><div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div><?php endif; ?>

                <?php if ($user): ?>
                <div style="margin-bottom:1rem;">
                    <a href="account_management.php" class="btn btn-outline btn-sm"><i class="fas fa-arrow-left"></i> Back to Account Management</a>
                </div>

                <div class="card" style="max-width:700px;">
                    <div class="card-header"><h3 class="card-title"><i class="fas fa-user-edit"></i> User Details</h3></div>
                    <div class="card-body">
                        <form method="POST" action="">
                            <?php csrf_token_input(); ?>
                            <div style="display:grid;grid-template-columns:1fr 1fr;gap:0 1rem;">
                                <div class="form-group"><label>Employee ID</label><input type="text" class="form-control" value="<?php echo htmlspecialchars($user['employee_id'] ?? ''); ?>" readonly disabled></div>
                                <div class="form-group"><label>ID Number</label><input type="text" class="form-control" value="<?php echo htmlspecialchars($user['id_number'] ?? ''); ?>" readonly disabled></div>
                            </div>
                            <div style="display:grid;grid-template-columns:2fr 1fr 2fr;gap:0 1rem;">
                                <div class="form-group"><label>First Name *</label><input type="text" name="first_name" class="form-control" required maxlength="50" value="<?php echo htmlspecialchars($user['first_name']); ?>"></div>
                                <div class="form-group"><label>Middle Initial</label><input type="text" name="middle_initial" class="form-control" maxlength="1" value="<?php echo htmlspecialchars($user['middle_initial'] ?? ''); ?>"></div>
                                <div class="form-group"><label>Last Name *</label><input type="text" name="last_name" class="form-control" required maxlength="50" value="<?php echo htmlspecialchars($user['last_name']); ?>"></div>
                            </div>
                            <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:0 1rem;">
                                <div class="form-group"><label>Extension Name</label><input type="text" name="extension_name" class="form-control" maxlength="10" placeholder="e.g., Jr." value="<?php echo htmlspecialchars($user['extension_name'] ?? ''); ?>"></div>
                                <div class="form-group"><label>Sex *</label>
                                    <select name="sex" class="form-control" required>
                                        <option value="Male" <?php echo $user['sex'] === 'Male' ? 'selected' : ''; ?>>Male</option>
                                        <option value="Female" <?php echo $user['sex'] === 'Female' ? 'selected' : ''; ?>>Female</option>
                                        <option value="Prefer not to say" <?php echo $user['sex'] === 'Prefer not to say' ? 'selected' : ''; ?>>Prefer not to say</option>
                                    </select>
                                </div>
                                <div class="form-group"><label>Birthdate *</label><input type="date" name="birthdate" class="form-control" required value="<?php echo htmlspecialchars($user['birthdate']); ?>"></div>
                            </div>
                            <div style="display:grid;grid-template-columns:1fr 1fr;gap:0 1rem;">
                                <div class="form-group"><label>Email *</label><input type="email" name="email" class="form-control" required maxlength="100" value="<?php echo htmlspecialchars($user['email']); ?>"></div>
                                <div class="form-group"><label>Contact Number *</label><input type="tel" name="contact_number" class="form-control" required maxlength="20" value="<?php echo htmlspecialchars($user['contact_number']); ?>"></div>
                            </div>
                            <div class="form-group"><label>Street</label><input type="text" name="address_street" class="form-control" maxlength="100" value="<?php echo htmlspecialchars($user['address_street'] ?? ''); ?>"></div>
                            <div style="display:grid;grid-template-columns:1fr 1fr;gap:0 1rem;">
                                <div class="form-group"><label>Barangay</label><input type="text" name="address_barangay" class="form-control" maxlength="100" value="<?php echo htmlspecialchars($user['address_barangay'] ?? ''); ?>"></div>
                                <div class="form-group"><label>City</label><input type="text" name="address_city" class="form-control" maxlength="100" value="<?php echo htmlspecialchars($user['address_city'] ?? ''); ?>"></div>
                            </div>
                            <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:0 1rem;">
                                <div class="form-group"><label>Province</label><input type="text" name="address_province" class="form-control" maxlength="100" value="<?php echo htmlspecialchars($user['address_province'] ?? ''); ?>"></div>
                                <div class="form-group"><label>Country</label><input type="text" name="address_country" class="form-control" maxlength="100" value="<?php echo htmlspecialchars($user['address_country'] ?? ''); ?>"></div>
                                <div class="form-group"><label>Zip Code</label><input type="text" name="zip_code" class="form-control" maxlength="10" value="<?php echo htmlspecialchars($user['zip_code'] ?? ''); ?>"></div>
                            </div>
                            <div style="display:grid;grid-template-columns:1fr 1fr;gap:0 1rem;">
                                <div class="form-group"><label>Role *</label>
                                    <select name="role" class="form-control" required>
                                        <option value="user" <?php echo ($user['role'] ?? 'user') === 'user' ? 'selected' : ''; ?>>User</option>
                                        <option value="admin" <?php echo ($user['role'] ?? '') === 'admin' ? 'selected' : ''; ?>>Admin</option>
                                        <option value="super_admin" <?php echo ($user['role'] ?? '') === 'super_admin' ? 'selected' : ''; ?>>Super Admin</option>
                                    </select>
                                </div>
                                <div class="form-group"><label>Account Status *</label>
                                    <select name="account_status" class="form-control" required>
                                        <option value="approved" <?php echo ($user['account_status'] ?? '') === 'approved' ? 'selected' : ''; ?>>Approved</option>
                                        <option value="inactive" <?php echo ($user['account_status'] ?? '') === 'inactive' ? 'selected' : ''; ?>>Inactive</option>
                                        <option value="blocked" <?php echo ($user['account_status'] ?? '') === 'blocked' ? 'selected' : ''; ?>>Blocked</option>
                                        <option value="pending" <?php echo ($user['account_status'] ?? '') === 'pending' ? 'selected' : ''; ?>>Pending</option>
                                        <option value="rejected" <?php echo ($user['account_status'] ?? '') === 'rejected' ? 'selected' : ''; ?>>Rejected</option>
                                    </select>
                                </div>
                            </div>
                            <div style="display:flex;gap:0.75rem;margin-top:1rem;">
                                <button type="submit" class="btn btn-primary"><i class="fas fa-save"></i> Save Changes</button>
                                <a href="account_management.php" class="btn btn-outline">Cancel</a>
                            </div>
                        </form>
                    </div>
                </div>
                <?php else: ?>
                <div class="card" style="max-width:700px;"><div class="card-body text-center" style="padding:2rem;"><p class="text-muted">No user selected.</p><a href="account_management.php" class="btn btn-primary"><i class="fas fa-arrow-left"></i> Back to Account Management</a></div></div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <div id="sidebarOverlay" class="sidebar-overlay" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('active');"></div>
</body>
</html>
