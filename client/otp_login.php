<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/csrf.php';

if (isset($_SESSION['user_id'])) { header('Location: dashboard.php'); exit(); }

if (empty($_SESSION['otp_user_id']) || ($_SESSION['otp_purpose'] ?? '') !== 'login') {
    header('Location: login.php');
    exit();
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token. Please try again.';
    } else {
        $otp_input = trim($_POST['otp'] ?? '');
        if ($otp_input === '' || strlen($otp_input) !== OTP_LENGTH) {
            $error = 'Please enter a valid ' . OTP_LENGTH . '-digit OTP.';
        } else {
            $result = verify_otp($pdo, 'users', (int)$_SESSION['otp_user_id'], $otp_input, 'login');
            if ($result['success']) {
                $user_id = (int)$_SESSION['otp_user_id'];
                $stmt = $pdo->prepare("SELECT id, username, first_name, last_name, email, role, account_status, id_number, must_change_password FROM users WHERE id = ? AND is_deleted = 0");
                $stmt->execute([$user_id]);
                $user = $stmt->fetch();

                if (!$user || $user['account_status'] === STATUS_BLOCKED) {
                    unset($_SESSION['otp_user_id'], $_SESSION['otp_purpose'], $_SESSION['otp_masked_id_number'], $_SESSION['otp_masked_email'], $_SESSION['otp_login_must_change']);
                    $error = $user ? 'Account is blocked.' : 'Account not found. Please log in again.';
                    if (!$user) { header('Location: login.php'); exit(); }
                } elseif ($user['account_status'] === STATUS_PENDING) {
                    unset($_SESSION['otp_user_id'], $_SESSION['otp_purpose'], $_SESSION['otp_masked_id_number'], $_SESSION['otp_masked_email'], $_SESSION['otp_login_must_change']);
                    header('Location: login.php');
                    exit();
                } elseif ($user['account_status'] === STATUS_REJECTED) {
                    unset($_SESSION['otp_user_id'], $_SESSION['otp_purpose'], $_SESSION['otp_masked_id_number'], $_SESSION['otp_masked_email'], $_SESSION['otp_login_must_change']);
                    $error = 'Your registration has been rejected. Please contact support.';
                } else {
                    $stmt = $pdo->prepare("UPDATE users SET last_login = NOW(), account_status = 'online' WHERE id = ?");
                    $stmt->execute([$user_id]);

                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['username'] = $user['username'];
                    $_SESSION['full_name'] = trim($user['first_name'] . ' ' . $user['last_name']);
                    $_SESSION['email'] = $user['email'];
                    $_SESSION['user_role'] = $user['role'] ?? 'user';
                    $_SESSION['account_status'] = 'online';
                    $_SESSION['id_number'] = $user['id_number'] ?? null;
                    $_SESSION['must_change_password'] = (int)($_SESSION['otp_login_must_change'] ?? (int)($user['must_change_password'] ?? 0));
                    $_SESSION['last_activity'] = time();

                    unset($_SESSION['otp_user_id'], $_SESSION['otp_purpose'], $_SESSION['otp_masked_id_number'], $_SESSION['otp_masked_email'], $_SESSION['otp_login_must_change']);

                    session_regenerate_id(true);
                    log_login($pdo, 'users', $user['id'], $user['username'], $_SESSION['full_name'], $user['role'] ?? 'user', 'login', 'success', $user['id_number']);
                    log_audit($pdo, 'login', 'users', $user['id'], $_SESSION['full_name'], 'User logged in');

                    if (!empty($_SESSION['must_change_password'])) {
                        header('Location: change_password.php');
                    } else {
                        header('Location: dashboard.php');
                    }
                    exit();
                }
            } else {
                $error = $result['message'];
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
    <title>Login Verification - MovieHub</title>
    <link rel="stylesheet" href="../assets/css/style.css?v=2.3.0">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body style="background: url('../assets/homepage.jpg') center/cover no-repeat fixed; background-color: #1a1a2e;">
    <?php require_once '../includes/header_public.php'; ?>

    <div class="auth-wrapper">
        <div class="auth-card">
            <div class="auth-logo">
                <i class="fas fa-film"></i>
                <h1>MovieHub</h1>
            </div>
            <h2 class="auth-title">Login Verification</h2>
            <p class="auth-subtitle">Enter the <?php echo OTP_LENGTH; ?>-digit code sent to your email</p>

            <?php if ($error): ?>
                <div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>

            <?php if (!empty($_SESSION['otp_masked_email'])): ?>
            <div class="alert alert-info" style="font-size:0.8125rem;display:flex;flex-direction:column;gap:0.25rem;">
                <span><i class="fas fa-id-card"></i> ID Number: <strong><?php echo htmlspecialchars($_SESSION['otp_masked_id_number'] ?? '****-****'); ?></strong></span>
                <span><i class="fas fa-envelope"></i> Email: <strong><?php echo htmlspecialchars($_SESSION['otp_masked_email']); ?></strong></span>
            </div>
            <?php endif; ?>

            <form method="POST" action="" class="auth-form">
                <?php csrf_token_input(); ?>
                <div class="form-group">
                    <label for="otp"><i class="fas fa-key"></i> OTP Code</label>
                    <input type="text" id="otp" name="otp" class="form-control" placeholder="Enter <?php echo OTP_LENGTH; ?>-digit code" required maxlength="<?php echo OTP_LENGTH; ?>" pattern="\d{<?php echo OTP_LENGTH; ?>}" inputmode="numeric" autocomplete="one-time-code">
                </div>
                <button type="submit" class="btn btn-primary btn-block"><i class="fas fa-check"></i> Verify &amp; Continue</button>
            </form>

            <div class="auth-links">
                <a href="#" onclick="resendOtp(); return false;" id="resendLink"><i class="fas fa-redo"></i> Resend OTP</a>
                <span id="resendTimer" style="display:none; color:var(--muted);"></span>
                <br>
                <a href="logout.php"><i class="fas fa-arrow-left"></i> Cancel and log out</a>
            </div>
        </div>
    </div>

    <?php require_once '../includes/footer.php'; ?>

    <script>
    var _resendSeconds = 60;
    var _resendTimerHandle = null;

    function startCooldown() {
        var link = document.getElementById('resendLink');
        var timer = document.getElementById('resendTimer');
        if (_resendTimerHandle) clearInterval(_resendTimerHandle);
        link.style.display = 'none';
        timer.style.display = 'inline';
        var endTime = Date.now() + (_resendSeconds * 1000);
        _resendTimerHandle = setInterval(function () {
            var remaining = Math.max(0, Math.round((endTime - Date.now()) / 1000));
            if (remaining > 0) {
                timer.textContent = 'Resend in ' + remaining + 's';
            } else {
                clearInterval(_resendTimerHandle);
                _resendTimerHandle = null;
                timer.style.display = 'none';
                link.style.display = 'inline';
            }
        }, 1000);
        tickOnce();
        function tickOnce() {
            var remaining = Math.max(0, Math.round((endTime - Date.now()) / 1000));
            timer.textContent = remaining > 0 ? 'Resend in ' + remaining + 's' : '';
        }
    }
    startCooldown();

    async function resendOtp() {
        try {
            const r = await fetch('resend_otp.php', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: 'csrf_token=' + encodeURIComponent('<?php echo $_SESSION['csrf_token']; ?>')
            });
            const data = await r.json();
            if (data.ok) { startCooldown(); alert('OTP resent! Check your email.'); }
            else { alert(data.message || 'Failed to resend OTP.'); }
        } catch(e) { alert('Network error. Please try again.'); }
    }
    </script>
</body>
</html>