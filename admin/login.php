<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';
require_once '../includes/csrf.php';

$auth = new Auth($pdo);

if (isset($_SESSION['admin_id'])) {
    if (($_SESSION['admin_role'] ?? '') === 'super_admin') { header('Location: ../superadmin/dashboard.php'); }
    else { header('Location: dashboard.php'); }
    exit();
}
if (isset($_SESSION['user_id'])) { header('Location: ../client/dashboard.php'); exit(); }

error_reporting(E_ALL);
ini_set('display_errors', 1);

$attemptKey = 'login_attempts_admin';
$lockKey = 'login_lock_until_admin';
$_SESSION[$attemptKey] = $_SESSION[$attemptKey] ?? 0;
$_SESSION[$lockKey] = $_SESSION[$lockKey] ?? 0;

$blocked = false;
$lockRemaining = 0;
if (!empty($_SESSION[$lockKey]) && $_SESSION[$lockKey] > time()) {
    $lockRemaining = $_SESSION[$lockKey] - time();
    $blocked = true;
}

$error = '';
$showForgot = ($_SESSION[$attemptKey] >= 1);

if ($_SERVER['REQUEST_METHOD'] == 'POST' && !$blocked) {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token. Please try again.';
    } else {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        if (empty($username) || empty($password)) {
            $error = 'Please fill in all fields.';
        } else {
            $result = $auth->login_admin($username, $password);
            if ($result['success']) {
                $_SESSION[$attemptKey] = 0;
                $_SESSION[$lockKey] = 0;
                if (!empty($_SESSION['pending_admin_setup'])) {
                    header('Location: change_password.php');
                } elseif (!empty($_SESSION['must_change_password'])) {
                    header('Location: change_password.php');
                } elseif (($result['role'] ?? '') === 'super_admin') {
                    header('Location: ../superadmin/dashboard.php');
                } else {
                    header('Location: dashboard.php');
                }
                exit();
            } else {
                $_SESSION[$attemptKey]++;
                $attempts = $_SESSION[$attemptKey];
                if ($attempts % LOCKOUT_THRESHOLD === 0) {
                    $cycle = $attempts / LOCKOUT_THRESHOLD;
                    $duration = LOCKOUT_INITIAL_SECONDS * pow(2, $cycle - 1);
                    $duration = min($duration, 3600);
                    $_SESSION[$lockKey] = time() + $duration;
                    $lockRemaining = $duration;
                    $blocked = true;
                }
                $error = $result['message'] ?? 'Invalid username or password.';
            }
        }
}
}
if ($error === '') { $fb = flash_message('error'); if ($fb) { $error = $fb; } }
$flash_success = flash_message('success');
generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login - MovieHub</title>
    <link rel="stylesheet" href="../assets/css/style.css?v=2.3.0">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        .btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .cop-disabled { pointer-events: none !important; opacity: 0.6 !important; }
    </style>
</head>
<body style="background: url('../assets/homepage.jpg') center/cover no-repeat fixed; background-color: #1a1a2e;">
    <?php require_once '../includes/header_public.php'; ?>

    <div class="auth-wrapper">
        <div class="auth-card">
            <div class="auth-logo">
                <i class="fas fa-cog"></i>
                <h1>MovieHub</h1>
            </div>
            <h2 class="auth-title">Admin Login</h2>
            <p class="auth-subtitle">Sign in to the admin panel</p>

<?php if ($error): ?>
                <div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            <?php if (!empty($flash_success)): ?>
                <div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($flash_success); ?></div>
            <?php endif; ?>

            <form method="POST" action="" class="auth-form">
                <?php csrf_token_input(); ?>
<div class="form-group">
                    <label for="username">Username or ID Number</label>
                    <input type="text" id="username" name="username" class="form-control" placeholder="Enter admin username or ID number" required>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" class="form-control" placeholder="Enter admin password" required>
                </div>
                <button type="submit" class="btn btn-primary btn-block" id="loginBtn" <?php echo $blocked ? 'disabled' : ''; ?>>
                    <i class="fas fa-sign-in-alt"></i> Login
                </button>
            </form>

            <div class="auth-links">
                <?php if ($showForgot): ?>
                    <a href="forgot_password.php"><i class="fas fa-key"></i> Forgot your password?</a>
                <?php endif; ?>
                <br>
                <a href="../client/login.php"><i class="fas fa-arrow-left"></i> Back to Client Login</a>
            </div>
        </div>
    </div>

    <?php require_once '../includes/footer.php'; ?>

    <script>
    <?php if ($blocked && $lockRemaining > 0): ?>
    const loginBtn = document.getElementById('loginBtn');
    let remainingTime = <?php echo $lockRemaining; ?> * 1000;
    loginBtn.disabled = true;

    function disablePage() {
        document.querySelectorAll('input, button').forEach(el => { try { el.disabled = true; } catch(e){} el.classList.add('cop-disabled'); });
    }
    function enablePage() {
        document.querySelectorAll('input, button').forEach(el => { try { el.disabled = false; } catch(e){} el.classList.remove('cop-disabled'); });
    }
    disablePage();

    function updateTimer() {
        if (remainingTime > 0) {
            const sec = Math.floor(remainingTime / 1000);
            const m = Math.floor(sec / 60); const s = sec % 60;
            loginBtn.textContent = 'Locked - ' + m + 'm ' + s + 's';
            remainingTime -= 1000;
            setTimeout(updateTimer, 1000);
        } else {
            loginBtn.disabled = false;
            loginBtn.innerHTML = '<i class="fas fa-sign-in-alt"></i> Login';
            enablePage();
        }
    }
    updateTimer();
    <?php else: ?>
    window.addEventListener('load', function() { document.getElementById('username').focus(); });
    <?php endif; ?>
    </script>
</body>
</html>
