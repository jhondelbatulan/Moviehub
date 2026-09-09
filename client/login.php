<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';
require_once '../includes/csrf.php';

$auth = new Auth($pdo);

if (isset($_SESSION['user_id'])) { header('Location: dashboard.php'); exit(); }
if (isset($_SESSION['admin_id'])) {
    if (($_SESSION['admin_role'] ?? '') === 'super_admin') { header('Location: ../superadmin/dashboard.php'); }
    else { header('Location: ../admin/dashboard.php'); }
    exit();
}
if (isset($_SESSION['super_admin_id'])) { header('Location: ../superadmin/dashboard.php'); exit(); }

if (!isset($_SESSION['login_attempts'])) { $_SESSION['login_attempts'] = 0; $_SESSION['lockout_until'] = 0; }

$error = '';
$blocked = ($_SESSION['lockout_until'] > time());
$showForgot = ($_SESSION['login_attempts'] >= 1);

if ($_SERVER['REQUEST_METHOD'] == 'POST' && !$blocked) {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token. Please try again.';
    } else {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        if (empty($username) || empty($password)) {
            $error = 'Please fill in all fields.';
        } else {
            $stmt = $pdo->prepare("SELECT account_status FROM users WHERE (username = ? OR id_number = ?) AND is_deleted = 0");
            $stmt->execute([$username, $username]);
            $existingUser = $stmt->fetch();
            if ($existingUser && $existingUser['account_status'] === STATUS_BLOCKED) {
                $error = 'Your account is blocked. Please contact support.';
            } else {
            $result = $auth->login_user($username, $password);
            if ($result['success']) {
                $_SESSION['login_attempts'] = 0;
                $_SESSION['lockout_until'] = 0;
                if ($_SESSION['user_role'] === ROLE_SUPER_ADMIN) {
                    header('Location: ../superadmin/dashboard.php');
                } else {
                    header('Location: dashboard.php');
                }
                exit();
            } else {
                $result2 = $auth->login_admin($username, $password);
                if ($result2['success']) {
                    $_SESSION['login_attempts'] = 0;
                    $_SESSION['lockout_until'] = 0;
                    if (!empty($_SESSION['must_change_password'])) {
                        header('Location: ../admin/change_password.php');
                    } elseif (($result2['role'] ?? '') === 'super_admin') {
                        header('Location: ../superadmin/dashboard.php');
                    } else {
                        header('Location: ../admin/dashboard.php');
                    }
                    exit();
                }
                $_SESSION['login_attempts']++;
                if ($_SESSION['login_attempts'] % LOCKOUT_THRESHOLD == 0) {
                    $cycle = $_SESSION['login_attempts'] / LOCKOUT_THRESHOLD;
                    $duration = LOCKOUT_INITIAL_SECONDS * pow(2, $cycle - 1);
                    $duration = min($duration, 3600);
                    $_SESSION['lockout_until'] = time() + $duration;
                    $blocked = true;
                }
                $error = $result['message'] ?? 'Invalid username or password.';
            }
            }
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
    <title>Login - MovieHub</title>
    <link rel="stylesheet" href="../assets/css/style.css?v=2.3.0">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        .btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .cop-disabled { pointer-events: none !important; opacity: 0.6 !important; }
        .cop-disabled[href] { cursor: not-allowed !important; }
        .password-wrapper { position: relative; }
        .password-wrapper .toggle-password {
            position: absolute; right: 12px; top: 50%; transform: translateY(-50%);
            color: var(--muted); font-size: 1rem; cursor: pointer;
            background: transparent; border: none; padding: 0;
            display: inline-flex; align-items: center; justify-content: center;
        }
        .password-wrapper .form-control { padding-right: 40px; }
    </style>
</head>
<body style="background: url('../assets/homepage.jpg') center/cover no-repeat fixed; background-color: #1a1a2e;">
    <?php require_once '../includes/header_public.php'; ?>

    <div class="auth-wrapper">
        <div class="auth-card">
            <div class="auth-logo">
                <i class="fas fa-film"></i>
                <h1>MovieHub</h1>
            </div>
            <h2 class="auth-title">Login</h2>
            <p class="auth-subtitle">Sign in to your account</p>

            <?php if ($error): ?>
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle"></i>
                    <?php echo htmlspecialchars($error); ?>
                </div>
            <?php endif; ?>

            <form method="POST" action="" class="auth-form" id="loginForm">
                <?php csrf_token_input(); ?>
                <div class="form-group">
                    <label for="username">Username or ID Number</label>
                    <input type="text" id="username" name="username" class="form-control" placeholder="Enter your username or ID number" required>
                </div>

                <div class="form-group">
                    <label for="password">Password</label>
                    <div class="password-wrapper">
                        <input type="password" id="password" name="password" class="form-control" placeholder="Enter your password" required>
                        <button type="button" class="toggle-password" id="togglePassword" aria-label="Show password" title="Show password">
                            <i class="fas fa-eye" aria-hidden="true"></i>
                        </button>
                    </div>
                </div>

                <button type="submit" class="btn btn-primary btn-block" id="loginBtn" <?php echo $blocked ? 'disabled' : ''; ?>>
                    <i class="fas fa-sign-in-alt"></i> Login
                </button>
            </form>

            <div class="auth-links">
                <a href="register.php">Don't have an account? Register here</a>
                <?php if ($showForgot): ?>
                    <a href="forgot_password.php"><i class="fas fa-key"></i> Forgot your password?</a>
                <?php endif; ?>
                <?php if ($blocked): ?>
                    <span id="lockoutTimer" style="display: inline-block; margin-left: 0.5rem; font-weight: 600; color: var(--info);"></span>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <?php require_once '../includes/footer.php'; ?>

    <script>
<?php if (!$blocked): ?>
window.addEventListener('load', function() {
    document.getElementById('username').focus();
});
<?php endif; ?>

<?php if ($blocked): ?>
const loginBtn = document.getElementById('loginBtn');
const lockoutTimer = document.getElementById('lockoutTimer');
let remainingTime = <?php echo max(0, $_SESSION['lockout_until'] - time()); ?> * 1000;
loginBtn.disabled = true;

function disablePageFunctions() {
    document.querySelectorAll('input, button, select, textarea').forEach(el => {
        try { el.dataset.disabled = el.disabled ? '1' : '0'; } catch(e){}
        try { el.disabled = true; } catch(e){}
        el.classList.add('cop-disabled');
    });
    document.querySelectorAll('a').forEach(a => {
        try { if (a.href) { a.dataset.href = a.href; a.removeAttribute('href'); } } catch(e){}
        a.classList.add('cop-disabled');
        a.setAttribute('aria-disabled', 'true');
    });
    try { history.pushState(null, null, location.href); window.addEventListener('popstate', onPopStatePrevent); } catch(e){}
    window.addEventListener('beforeunload', beforeUnloadHandler);
}

function enablePageFunctions() {
    document.querySelectorAll('input, button, select, textarea').forEach(el => {
        try { el.disabled = false; } catch(e){}
        el.classList.remove('cop-disabled');
    });
    document.querySelectorAll('a').forEach(a => {
        try { if (a.dataset.href) { a.setAttribute('href', a.dataset.href); delete a.dataset.href; } } catch(e){}
        a.classList.remove('cop-disabled');
        a.removeAttribute('aria-disabled');
    });
    try { window.removeEventListener('popstate', onPopStatePrevent); } catch(e){}
    window.removeEventListener('beforeunload', beforeUnloadHandler);
}

function onPopStatePrevent(e) { try { history.pushState(null, null, location.href); } catch(e){} }
function beforeUnloadHandler(e) { const msg = 'You are temporarily locked out.'; e.returnValue = msg; return msg; }

disablePageFunctions();

function updateLockoutTimer() {
    if (remainingTime > 0) {
        const seconds = Math.floor(remainingTime / 1000);
        const minutes = Math.floor(seconds / 60);
        const sec = seconds % 60;
        lockoutTimer.textContent = 'Try again in ' + minutes + 'm ' + sec + 's';
        remainingTime -= 1000;
        setTimeout(updateLockoutTimer, 1000);
    } else {
        lockoutTimer.textContent = '';
        loginBtn.disabled = false;
        enablePageFunctions();
    }
}
updateLockoutTimer();
<?php endif; ?>

(function() {
    const toggleBtn = document.getElementById('togglePassword');
    const pwd = document.getElementById('password');
    if (!toggleBtn || !pwd) return;
    const icon = toggleBtn.querySelector('i');
    function setState(show) {
        pwd.type = show ? 'text' : 'password';
        toggleBtn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
        toggleBtn.title = show ? 'Hide password' : 'Show password';
        if (icon) { icon.classList.toggle('fa-eye', !show); icon.classList.toggle('fa-eye-slash', show); }
    }
    toggleBtn.addEventListener('click', function(e) { e.preventDefault(); setState(pwd.type === 'password'); });
    toggleBtn.addEventListener('keydown', function(e) { if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); setState(pwd.type === 'password'); } });
})();
    </script>
</body>
</html>
