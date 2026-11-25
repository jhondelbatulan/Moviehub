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
        $role_stmt = $pdo->prepare('SELECT role FROM users WHERE id = ? AND is_deleted = 0');
        $role_stmt->execute([$user_id]);
        $role = $role_stmt->fetchColumn();
        if ($role === false) $error = 'User not found.';

        if ($first_name === '' || $last_name === '' || $email === '' || $birthdate === '' || $contact_number === '') {
            $error = 'Please fill in all required fields.';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = 'Invalid email address.';
        } elseif (!in_array($sex, ['Male', 'Female', 'Prefer not to say'], true)) {
            $error = 'Invalid sex value.';
        } elseif (($e = validate_name_field($first_name)) !== '') {
            $error = $e;
        } elseif (($e = validate_name_field($last_name)) !== '') {
            $error = $e;
        } elseif (($e = validate_middle_initial($middle_initial)) !== '') {
            $error = $e;
        } elseif (($e = validate_extension_name($extension_name)) !== '') {
            $error = $e;
        } elseif (($e = validate_birthdate($birthdate)) !== '') {
            $error = $e;
        } elseif (($e = validate_ph_contact($contact_number)) !== '') {
            $error = 'Contact number must be a valid Philippine mobile number (e.g. 0917-123-4567).';
        } elseif (($e = validate_address_field($address_street, 'Street')) !== '') {
            $error = $e;
        } elseif (($e = validate_address_field($address_barangay, 'Barangay')) !== '') {
            $error = $e;
        } elseif (($e = validate_address_field($address_city, 'City')) !== '') {
            $error = $e;
        } elseif (($e = validate_address_field($address_province, 'Province')) !== '') {
            $error = $e;
        } elseif (($e = validate_address_field($address_country, 'Country')) !== '') {
            $error = $e;
        } elseif ($zip_code !== '' && (!ctype_digit($zip_code) || strlen($zip_code) < 4)) {
            $error = 'Zip code must be a valid number (4+ digits).';
        } else {
            try {
                $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ? AND id != ?");
                $stmt->execute([$email, $user_id]);
                if ($stmt->fetch()) {
                    $error = 'That email address is already used by another account.';
                } else {
                    $stmt = $pdo->prepare("UPDATE users SET first_name = ?, middle_initial = ?, last_name = ?, extension_name = ?, sex = ?, birthdate = ?, email = ?, contact_number = ?, address_street = ?, address_barangay = ?, address_city = ?, address_province = ?, address_country = ?, zip_code = ? WHERE id = ?");
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
                        $user_id
                    ]);
                    log_audit($pdo, 'profile_update', 'users', $user_id, $first_name . ' ' . $last_name, 'User account details updated');
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
<div style="display:grid;grid-template-columns:1fr;gap:0 1rem;">
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
                                <div class="form-group"><label>Role</label><input type="text" class="form-control" value="<?php echo htmlspecialchars(ucfirst(str_replace('_', ' ', $user['role'] ?? 'user'))); ?>" readonly disabled></div>
<div class="form-group"><label>Account Status</label><input type="text" class="form-control" value="<?php echo htmlspecialchars(ucfirst($user['account_status'] ?? '')); ?>" readonly disabled></div>
                                <div class="form-group"><label>Age</label><input type="text" id="ageDisplay" class="form-control" readonly value="<?php echo $user['birthdate'] ? (compute_age($user['birthdate']) . ' years') : ''; ?>" placeholder="Auto-computed from birthdate"></div>
                            </div>
                            <div style="display:flex;gap:0.75rem;margin-top:1rem;">
                                <button type="submit" class="btn btn-primary"><i class="fas fa-save"></i> Save Changes</button>
                                <a href="account_management.php" class="btn btn-outline">Cancel</a>
                            </div>
                        </form>
                        <script>
                        (function () {
                            var bd = document.getElementsByName('birthdate')[0], age = document.getElementById('ageDisplay');
                            if (!bd || !age) return;
                            function upd() {
                                var d = bd.value;
                                if (!d) { age.value = ''; return; }
                                var b = new Date(d), n = new Date(), y = n.getFullYear() - b.getFullYear(), m = n.getMonth() - b.getMonth();
                                if (m < 0 || (m === 0 && n.getDate() < b.getDate())) y--;
                                age.value = (y >= 0 && y < 200) ? y + ' years' : '';
                            }
                            bd.addEventListener('input', upd);
                        })();
                        </script>
                        <script>
                        (function () {
                            function nameOk(v) {
                                v = v.trim();
                                if (!v) return false;
                                if (v.length < 2 || v.length > 30) return false;
                                if (!/^[A-Z][a-z]+(?: [A-Z][a-z]+)*$/.test(v)) return false;
                                if (/^[A-Z]+$/.test(v)) return false;
                                if (/[0-9]/.test(v) || /[^A-Za-z ]/.test(v)) return false;
                                if (/(.)\1{2,}/.test(v)) return false;
                                return true;
                            }
                            function phOk(v) { v = v.trim(); var n = v.replace(/[^0-9]/g, ''); if (n.indexOf('63') === 0) n = n.substring(2); if (n.indexOf('0') === 0) n = n.substring(1); return /^9\d{9}$/.test(n); }
                            var fn = document.getElementsByName('first_name')[0], ln = document.getElementsByName('last_name')[0], cn = document.getElementsByName('contact_number')[0];
                            var fnS = document.createElement('small'), lnS = document.createElement('small'), cnS = document.createElement('small');
                            [fnS, lnS, cnS].forEach(function (s) { s.style.display = 'block'; s.style.fontSize = '0.6875rem'; s.style.minHeight = '0.9em'; });
                            fn.parentNode.appendChild(fnS); ln.parentNode.appendChild(lnS); cn.parentNode.appendChild(cnS);
                            function set(el, ok, msg) { el.textContent = msg; el.style.color = ok ? 'var(--success)' : 'var(--danger)'; }
                            fn.addEventListener('input', function () { var v = this.value.trim(); nameOk(v) ? set(fnS, true, 'Valid') : set(fnS, false, v ? 'First letter capital, rest lowercase, no numbers/special chars.' : ''); });
                            ln.addEventListener('input', function () { var v = this.value.trim(); nameOk(v) ? set(lnS, true, 'Valid') : set(lnS, false, v ? 'First letter capital, rest lowercase, no numbers/special chars.' : ''); });
                            cn.addEventListener('input', function () { var v = this.value.trim(); phOk(v) ? set(cnS, true, 'Valid') : set(cnS, false, v ? 'Use PH format, e.g. 0917-123-4567' : ''); });
                        })();
                        </script>
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
