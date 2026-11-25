<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/authorization.php';
require_once '../includes/auth.php';
require_once '../includes/csrf.php';
require_once '../includes/otp.php';

require_login();
require_role('super_admin');
require_permission('admins.create');

$auth = new Auth($pdo);
$success = '';
$success_class = 'success';
$error = '';
$role = 'admin';
$created_query = '';

if ($_SERVER['REQUEST_METHOD'] == 'GET' && isset($_GET['resend'])) {
    $resend_user = $_GET['resend'];
    if (isset($_SESSION['created_credentials'][$resend_user])) {
        $c = $_SESSION['created_credentials'][$resend_user];
        $email_sent = send_account_credentials_email($c['email'], $resend_user, $c['password'], $c['role']);
        if ($email_sent) {
            $success_class = 'success';
            $success = 'The credentials email was resent successfully to <strong>' . htmlspecialchars($c['email']) . '</strong>.';
            unset($_SESSION['created_credentials'][$resend_user]);
        } else {
            $err_detail = '';
            if (!empty($_SESSION['last_mail_error'])) {
                $err_detail = ' <span class="text-muted">(Technical detail: ' . htmlspecialchars($_SESSION['last_mail_error']) . ')</span>';
                unset($_SESSION['last_mail_error']);
            }
            $success_class = 'warning';
            $success = 'The credentials email could NOT be sent again to <strong>' . htmlspecialchars($c['email']) . '</strong>. <a href="?resend=' . urlencode($resend_user) . '">Mail not received? Click here to try again.</a>' . $err_detail;
        }
    } else {
        $error = 'No pending credentials are available to resend for that account.';
    }
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token.';
    } else {
        $role = $_POST['role'] ?? 'admin';
        $username = trim($_POST['username'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $id_number = get_next_id_number($pdo);

        $role_label = $role === 'user' ? 'User' : ($role === 'super_admin' ? 'Super Admin' : 'Admin');
        $usernamePattern = '/^(?=.{3,30}$)[A-Za-z](?!.*([._])\1)[A-Za-z0-9._]*[A-Za-z0-9]$/';

        if (empty($username) || empty($email) || empty($password)) {
            $error = 'All required fields must be filled.';
        } elseif (!in_array($role, ['admin', 'super_admin', 'user'], true)) {
            $error = 'Invalid role.';
        } elseif (!preg_match($usernamePattern, $username)) {
            $error = 'Username must start with a letter, end with a letter/digit, and use only letters, numbers, underscores or dots (3-30 characters).';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = 'Invalid email address.';
        } elseif (($password_error = validate_strong_password($password)) !== '') {
            $error = $password_error;
        } else {
            $result = $auth->create_account([
                'role' => $role,
                'id_number' => $id_number,
                'username' => $username,
                'email' => $email,
                'password' => $password,
            ], $_SESSION['admin_role'], $_SESSION['admin_id'] ?? null, $_SESSION['admin_full_name'] ?? '');

            if ($result['success']) {
                $created_query = $id_number;
                $success_class = 'success';
                $send_credentials = in_array($role, ['admin', 'super_admin'], true);
                if ($send_credentials) {
                    $email_sent = send_account_credentials_email($email, $username, $password, $role);
                    if ($email_sent) {
                        $success = $role_label . ' account created. The credentials were emailed to <strong>' . htmlspecialchars($email) . '</strong>. The new account holder must complete profile, password, and security-question setup before opening the dashboard.';
                    } else {
                        $err_detail = '';
                        if (!empty($_SESSION['last_mail_error'])) {
                            $err_detail = ' <span class="text-muted">(Technical detail: ' . htmlspecialchars($_SESSION['last_mail_error']) . ')</span>';
                            unset($_SESSION['last_mail_error']);
                        }
                        $success_class = 'warning';
                        $success = $role_label . ' account created, but the credentials email could NOT be sent to <strong>' . htmlspecialchars($email) . '</strong>. <a href="?resend=' . urlencode($username) . '">Retry email</a>. Share these credentials securely: Username: <code>' . htmlspecialchars($username) . '</code> — Password: <code>' . htmlspecialchars($password) . '</code>' . $err_detail;
                    }
                    if (in_array($role, ['admin', 'super_admin'], true)) {
                        $_SESSION['created_credentials'][$username] = ['email' => $email, 'password' => $password, 'role' => $role];
                    }
                } else {
                    $success = $role_label . ' account created with the custom password you set. Credentials were not emailed for this User account.';
                }
                $role = 'admin';
            } else {
                $error = $result['message'];
            }
        }
    }
}

$form_values = ($error !== '' && $_SERVER['REQUEST_METHOD'] === 'POST') ? $_POST : [];
$form_role = in_array(($form_values['role'] ?? $role), ['admin', 'super_admin', 'user'], true) ? ($form_values['role'] ?? $role) : 'admin';
$super_admin_count = count_super_admin_accounts($pdo);
$super_admin_limit_reached = $super_admin_count >= 2;
$next_id = get_next_id_number($pdo);
generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create Account - MovieHub</title>
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
                    <div><h1 class="page-title">Create Account</h1><p class="page-subtitle">Create a new user, admin, or super admin account</p></div>
                </div>
            </div>

            <div class="content-body">
<?php if ($success): ?>
                <div class="alert alert-<?php echo $success_class; ?>"><i class="fas fa-check-circle"></i> <?php echo $success; ?></div>
<?php endif; ?>
                <?php if ($error): ?><div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div><?php endif; ?>

                <div class="card" style="max-width:760px;">
                    <div class="card-header"><h3 class="card-title"><i class="fas fa-user-plus"></i> New Account</h3></div>
                    <div class="card-body">
                        <form method="POST" action="" novalidate id="caForm">
                            <?php csrf_token_input(); ?>
                            <div class="ca-grid">
                                <div class="form-group"><label>Role *</label>
                                    <select name="role" class="form-control" required>
                                        <option value="super_admin" <?php echo $form_role === 'super_admin' ? 'selected' : ''; ?> <?php echo $super_admin_limit_reached ? 'disabled' : ''; ?>>Super Admin<?php echo $super_admin_limit_reached ? ' (limit reached)' : ''; ?></option>
                                        <option value="admin" <?php echo $form_role === 'admin' ? 'selected' : ''; ?>>Admin</option>
                                        <option value="user" <?php echo $form_role === 'user' ? 'selected' : ''; ?>>User</option>
                                    </select>
                                </div>
                                <div class="form-group"><label>ID Number</label>
                                    <input type="text" id="id_number" class="form-control" value="<?php echo htmlspecialchars($next_id); ?>" readonly>
                                    <small class="ca-status" style="color:var(--muted);">Auto-generated, in sequence based on the database</small>
                                </div>
                                <div class="form-group"><label>Username *</label><input type="text" name="username" class="form-control" required placeholder="e.g., juan_cruz, juan.cruz, juancruz123" autocomplete="off" value="<?php echo htmlspecialchars($form_values['username'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"><small id="usernameStatus" class="ca-status"></small></div>
                                <div class="form-group"><label>Email *</label><input type="email" name="email" id="email" class="form-control" required placeholder="For sending account credentials" autocomplete="email" value="<?php echo htmlspecialchars($form_values['email'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"><small id="emailStatus" class="ca-status" aria-live="polite"></small></div>
                                <div class="form-group ca-full"><label>Password *</label>
                                    <input type="password" id="password" name="password" class="form-control" required minlength="8" maxlength="30" autocomplete="new-password" spellcheck="false">
                                    <div class="pw-strength" aria-live="polite"><span id="pwStrengthBar"></span></div>
                                    <small id="pwStrengthText" class="ca-status" style="color:var(--muted);">Enter a password (8-30 characters).</small>
                                </div>
                            </div>

                            <?php if ($super_admin_limit_reached): ?><div class="alert alert-warning" style="margin-top:0.75rem;font-size:0.8125rem;"><i class="fas fa-exclamation-triangle"></i> The maximum of 2 Super Admin accounts has been reached. You can still create Admin or User accounts.</div><?php endif; ?>
                            <div class="alert alert-info" style="margin-top:0.75rem;font-size:0.8125rem;"><i class="fas fa-info-circle"></i> Admin and Super Admin credentials (including custom passwords) will be emailed to the entered address. The new account holder must complete their name, new password, and 3 security questions on first login; setup activates the new account and deactivates the previous active account of the same role.</div>
                            <button type="submit" class="btn btn-primary" style="width:100%;margin-top:0.75rem;"><i class="fas fa-user-plus"></i> Create Account</button>
                        </form>
                        <style>
                            .ca-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:0.5rem 1rem;}
                            .ca-grid .ca-full{grid-column:1/-1;}
                            .ca-grid .form-group{margin-bottom:0.25rem;}
                            .ca-grid .form-group label{font-size:0.75rem;font-weight:600;margin-bottom:0.25rem;display:block;color:var(--text-light);}
                            .ca-grid .form-control{height:34px;font-size:0.8125rem;background:#1a2234;border:1px solid #2e3a52;color:#f1f5f9;color-scheme:dark;}
                            .ca-grid .form-control::placeholder{color:#8fa0b8;opacity:1;}
                            .ca-grid .form-control:focus{border-color:var(--primary);}
                            .ca-status{font-size:0.6875rem;display:block;min-height:0.9em;line-height:1.2;}
                            .pw-strength{height:5px;margin-top:0.45rem;background:#2e3a52;border-radius:9px;overflow:hidden;}
                            .pw-strength span{display:block;width:0;height:100%;transition:width .2s,background .2s;}
                            @media(max-width:560px){.ca-grid{grid-template-columns:1fr;}.ca-grid .ca-full{grid-column:1/-1;}}
                        </style>
                        <script>
                        function setStatus(id, msg, ok){ var el=document.getElementById(id); if(el){ el.textContent=msg; el.style.color = ok?'var(--success)':'var(--danger)'; } }
                        var usernameRe = /^(?=.{3,30}$)[A-Za-z](?!.*([._])\1)[A-Za-z0-9._]*[A-Za-z0-9]$/;
                        document.getElementsByName('username')[0].addEventListener('input',function(){ var v=this.value.trim(); usernameRe.test(v)?setStatus('usernameStatus','Valid',true):setStatus('usernameStatus', v?'Start with a letter; 3-30 chars; letters, numbers, _ or . only':'' , false); });
                        var emailInput = document.getElementById('email'), emailTimer, emailCheck = 0;
                        async function checkEmailAvailability() {
                            var value = emailInput.value.trim(), status = document.getElementById('emailStatus'), checkId = ++emailCheck;
                            clearTimeout(emailTimer); emailInput.setCustomValidity('');
                            if (!value) { status.textContent = ''; return; }
                            if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) { status.textContent = 'Enter a valid email address.'; status.style.color = 'var(--danger)'; emailInput.setCustomValidity('Enter a valid email address.'); return; }
                            status.textContent = 'Checking email…'; status.style.color = 'var(--muted)'; emailInput.setCustomValidity('Checking email availability.');
                            emailTimer = setTimeout(async function () {
                                try {
                                    var response = await fetch('check_email.php?email=' + encodeURIComponent(value), {headers:{'Accept':'application/json'}});
                                    var result = await response.json();
                                    if (checkId !== emailCheck || value !== emailInput.value.trim()) return;
                                    if (result.ok) {
                                        status.textContent = result.available ? 'Email available' : 'Email already used';
                                        status.style.color = result.available ? 'var(--success)' : 'var(--danger)';
                                        emailInput.setCustomValidity(result.available ? '' : 'Email already used. Enter a different email address.');
                                    } else { status.textContent = 'Could not verify email right now.'; status.style.color = 'var(--warning)'; emailInput.setCustomValidity(''); }
                                } catch (e) { if (checkId === emailCheck) { status.textContent = 'Could not verify email right now.'; status.style.color = 'var(--warning)'; emailInput.setCustomValidity(''); } }
                            }, 350);
                        }
                        emailInput.addEventListener('input', checkEmailAvailability);
                        if (emailInput.value.trim()) checkEmailAvailability();
                        document.getElementById('caForm').addEventListener('submit', function (event) {
                            if (emailInput.validationMessage) { event.preventDefault(); emailInput.reportValidity(); }
                        });
                        var pwInput = document.getElementById('password');
                        if (pwInput.value) pwInput.dispatchEvent(new Event('input'));
                        pwInput.addEventListener('input', function(){
                            var value = pwInput.value;
                            var categories = (/[A-Za-z]/.test(value)?1:0) + (/[0-9]/.test(value)?1:0) + (/[^A-Za-z0-9]/.test(value)?1:0);
                            var strength = value.length < 8 || categories < 2 ? 'Weak' : (value.length >= 12 && categories === 3 ? 'Strong' : 'Medium');
                            var bar = document.getElementById('pwStrengthBar');
                            var label = document.getElementById('pwStrengthText');
                            bar.style.width = strength === 'Weak' ? '33%' : (strength === 'Medium' ? '66%' : '100%');
                            bar.style.background = strength === 'Weak' ? 'var(--danger)' : (strength === 'Medium' ? 'var(--warning)' : 'var(--success)');
                            label.textContent = value ? strength + (strength === 'Weak' ? ' — use at least 8 characters and combine letters with numbers or symbols.' : ' password') : 'Enter a password (8-30 characters).';
                            label.style.color = strength === 'Weak' ? 'var(--danger)' : (strength === 'Medium' ? 'var(--warning)' : 'var(--success)');
                        });
                        </script>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div id="sidebarOverlay" class="sidebar-overlay" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('active');"></div>
</body>
</html>
