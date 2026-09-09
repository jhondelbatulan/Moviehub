<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/authorization.php';
require_once '../includes/csrf.php';

require_login();

if (!isset($_SESSION['admin_id'])) {
    header('Location: login.php');
    exit();
}

$success = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token. Please try again.';
    } else {
        $new_password = $_POST['new_password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';

        if (strlen($new_password) < 8 || strlen($new_password) > 30) {
            $error = 'Password must be 8-30 characters.';
        } elseif ($new_password !== $confirm_password) {
            $error = 'Passwords do not match.';
        } else {
            $hashed = password_hash($new_password, PASSWORD_DEFAULT);
            $stmt = $pdo->prepare("UPDATE admin_users SET password = ?, must_change_password = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?");
            $stmt->execute([$hashed, $_SESSION['admin_id']]);
            $_SESSION['must_change_password'] = 0;
            $_SESSION['show_edit_profile_notice'] = true;
            $success = 'Password changed successfully. Redirecting to your dashboard...';
            $redirect_after = ($_SESSION['admin_role'] ?? '') === 'super_admin' ? '../superadmin/dashboard.php' : 'dashboard.php';
        }
    }
}
generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Change Password - MovieHub</title>
    <link rel="stylesheet" href="../assets/css/style.css?v=2.3.0">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        .cp-wrapper { min-height:100vh; display:flex; align-items:center; justify-content:center; padding:1.5rem; background:url('../assets/homepage.jpg') center/cover no-repeat fixed; background-color:#1a1a2e; }
        .cp-card { background:rgba(18,24,38,0.95); backdrop-filter:blur(16px); border-radius:var(--radius-xl); box-shadow:0 20px 60px rgba(0,0,0,0.5); width:100%; max-width:480px; border:1px solid var(--border-dark); padding:2rem; }
        .pw-toggle { position:absolute; right:12px; top:50%; transform:translateY(-50%); background:none; border:none; cursor:pointer; color:var(--text-light); font-size:1rem; }
        .password-wrapper { position:relative; } .password-wrapper .form-control { padding-right:40px; }
    </style>
</head>
<body>
    <div class="cp-wrapper">
        <div class="cp-card">
            <div class="auth-logo"><i class="fas fa-key"></i><h1>MovieHub</h1></div>
            <h2 class="auth-title">Change Password</h2>
            <p class="auth-subtitle">You must change your password before continuing.</p>

            <div class="alert alert-warning" style="margin-top:1rem;font-size:0.875rem;">
                <i class="fas fa-exclamation-triangle"></i> <strong>Notice:</strong> Your account is new or your password was set by a Super Administrator. For security, you are required to <strong>change your password</strong> on your first login before you can access the admin panel.
            </div>

            <?php if ($success): ?>
                <div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($success); ?></div>
                <script>setTimeout(function(){ window.location.href = '<?php echo htmlspecialchars($redirect_after); ?>'; }, 2000);</script>
            <?php endif; ?>
            <?php if ($error): ?>
                <div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>

            <?php if (!$success): ?>
            <form method="POST" action="" class="auth-form" id="cpForm">
                <?php csrf_token_input(); ?>
                <div class="form-group">
                    <label for="new_password"><i class="fas fa-lock"></i> New Password</label>
                    <div class="password-wrapper">
                        <input type="password" id="new_password" name="new_password" class="form-control" placeholder="8-30 characters" required minlength="8" maxlength="30" autocomplete="new-password">
                        <button type="button" class="pw-toggle" onclick="togglePass('new_password',this)" tabindex="-1"><i class="fas fa-eye"></i></button>
                    </div>
                    <small id="passwordStrength" style="font-size:0.75rem;"></small>
                </div>
                <div class="form-group">
                    <label for="confirm_password"><i class="fas fa-lock"></i> Confirm New Password</label>
                    <div class="password-wrapper">
                        <input type="password" id="confirm_password" name="confirm_password" class="form-control" placeholder="Re-enter new password" required autocomplete="new-password">
                        <button type="button" class="pw-toggle" onclick="togglePass('confirm_password',this)" tabindex="-1"><i class="fas fa-eye"></i></button>
                    </div>
                    <small id="confirmStatus" style="font-size:0.75rem;"></small>
                </div>
                <button type="submit" class="btn btn-primary btn-block"><i class="fas fa-check"></i> Change Password</button>
            </form>
            <div class="auth-links" style="text-align:center;margin-top:1rem;">
                <a href="../client/logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a>
            </div>
            <?php endif; ?>
        </div>
    </div>

    <script>
    function togglePass(id, btn) {
        var inp = document.getElementById(id);
        var isPwd = inp.type === 'password';
        inp.type = isPwd ? 'text' : 'password';
        btn.querySelector('i').classList.toggle('fa-eye');
        btn.querySelector('i').classList.toggle('fa-eye-slash');
    }
    document.getElementById('new_password').addEventListener('input', function() {
        var p = this.value; var meter = document.getElementById('passwordStrength'); var score = 0;
        if (p.length >= 8) score++;
        if (/[a-z]/.test(p) && /[A-Z]/.test(p)) score++;
        if (/\d/.test(p)) score++;
        if (/[^A-Za-z0-9]/.test(p)) score++;
        var labels = ['Weak','Medium','Strong','Very Strong']; var colors = ['var(--danger)','var(--warning)','var(--success)','var(--success)'];
        if (p.length > 0) { meter.textContent = labels[Math.max(0,score-1)]; meter.style.color = colors[Math.max(0,score-1)]; } else { meter.textContent = ''; }
        checkConfirm();
    });
    function checkConfirm() {
        var ok = document.getElementById('new_password').value === document.getElementById('confirm_password').value && document.getElementById('confirm_password').value.length > 0;
        var s = document.getElementById('confirmStatus');
        s.textContent = document.getElementById('confirm_password').value.length ? (ok ? 'Passwords match' : 'Passwords do not match') : '';
        s.style.color = ok ? 'var(--success)' : 'var(--danger)';
    }
    document.getElementById('confirm_password').addEventListener('input', checkConfirm);
    </script>
</body>
</html>
