<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/otp.php';
require_once '../includes/csrf.php';

if (empty($_SESSION['otp_user_id']) || empty($_SESSION['otp_purpose'])) {
    header('Location: forgot_password.php');
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
            $result = verify_otp($pdo, 'users', $_SESSION['otp_user_id'], $otp_input, $_SESSION['otp_purpose']);
            if ($result['success']) {
                $_SESSION['reset_verified_user_id'] = $_SESSION['otp_user_id'];
                unset($_SESSION['otp_user_id'], $_SESSION['otp_purpose']);
                header('Location: verify_security_after_otp.php');
                exit();
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
    <title>Verify OTP - MovieHub</title>
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
            <h2 class="auth-title">Verify OTP</h2>
            <p class="auth-subtitle">Enter the <?php echo OTP_LENGTH; ?>-digit code sent to your email</p>

            <?php if ($error): ?>
                <div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>

            <form method="POST" action="" class="auth-form">
                <?php csrf_token_input(); ?>
                <div class="form-group">
                    <label for="otp"><i class="fas fa-key"></i> OTP Code</label>
                    <input type="text" id="otp" name="otp" class="form-control" placeholder="Enter <?php echo OTP_LENGTH; ?>-digit code" required maxlength="<?php echo OTP_LENGTH; ?>" pattern="\d{<?php echo OTP_LENGTH; ?>}" inputmode="numeric" autocomplete="one-time-code">
                </div>
                <button type="submit" class="btn btn-primary btn-block"><i class="fas fa-check"></i> Verify OTP</button>
            </form>

            <div class="auth-links">
                <a href="#" onclick="resendOtp(); return false;" id="resendLink"><i class="fas fa-redo"></i> Resend OTP</a>
                <span id="resendTimer" style="display:none; color:var(--muted);"></span>
                <br>
                <a href="forgot_password.php"><i class="fas fa-arrow-left"></i> Use a different email</a>
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
