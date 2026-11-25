<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';
require_once '../includes/otp.php';
require_once '../includes/csrf.php';

if (isset($_SESSION['user_id'])) { header('Location: dashboard.php'); exit(); }

// Cancel link: discard the pending registration entirely.
if (isset($_GET['cancel'])) {
    unset($_SESSION['pending_registration'], $_SESSION['pending_registration_otp_key'],
          $_SESSION['pending_registration_email'], $_SESSION['pending_reg_otp_sent_at']);
    header('Location: register.php');
    exit();
}

// Without a pending registration there is nothing to verify.
if (empty($_SESSION['pending_registration']) || empty($_SESSION['pending_registration_otp_key'])) {
    header('Location: register.php');
    exit();
}

$auth = new Auth($pdo);
$error = '';
$success = '';
$otp_key = (int)$_SESSION['pending_registration_otp_key'];
$masked_email = mask_email($_SESSION['pending_registration_email'] ?? '');

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token. Please try again.';
    } elseif (isset($_POST['resend'])) {
        // Inline resend: resend_otp.php needs a real otp_user_id, which does
        // not exist yet for a pending registration.
        $cooldown_left = OTP_RESEND_COOLDOWN - (time() - (int)($_SESSION['pending_reg_otp_sent_at'] ?? 0));
        if ($cooldown_left > 0) {
            $error = 'Please wait ' . $cooldown_left . ' second(s) before resending the OTP.';
        } elseif (!can_resend_otp($pdo, 'users', $otp_key, 'verification')) {
            $error = 'Too many OTP requests. Please wait before trying again.';
        } else {
            $pending = $_SESSION['pending_registration'];
            $otp = create_otp($pdo, 'users', $otp_key, 'verification');
            send_otp_email($pending['email'], $otp, $pending['first_name'] . ' ' . $pending['last_name'], 'verification');
            $_SESSION['pending_reg_otp_sent_at'] = time();
            $success = 'A new verification code has been sent to your email.';
        }
    } else {
        $otp_input = trim($_POST['otp'] ?? '');
        if ($otp_input === '' || strlen($otp_input) !== OTP_LENGTH) {
            $error = 'Please enter a valid ' . OTP_LENGTH . '-digit OTP.';
        } else {
            $result = verify_otp($pdo, 'users', $otp_key, $otp_input, 'verification');
            if ($result['success']) {
                // Email verified: now create the account, which also submits
                // the approval request. register_user() re-checks duplicates.
                $reg = $auth->register_user($_SESSION['pending_registration']);
                unset($_SESSION['pending_registration'], $_SESSION['pending_registration_otp_key'],
                      $_SESSION['pending_registration_email'], $_SESSION['pending_reg_otp_sent_at']);
                if ($reg['success']) {
                    $success = 'Email verified! Your account has been submitted and is now pending admin approval. You will receive your login credentials via email once approved.';
                } else {
                    $error = $reg['message'];
                }
            } else {
                $error = $result['message'];
            }
        }
    }
}
generate_csrf_token();

$cooldown_left = max(0, OTP_RESEND_COOLDOWN - (time() - (int)($_SESSION['pending_reg_otp_sent_at'] ?? 0)));
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Your Email - MovieHub</title>
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

            <?php if ($success && !empty($_SESSION['pending_registration'])): ?>
                <h2 class="auth-title">Verification Code Resent</h2>
                <p class="auth-subtitle">Enter the <?php echo OTP_LENGTH; ?>-digit code sent to your email</p>
            <?php elseif ($success): ?>
                <div style="text-align:center; padding: 1rem 0;">
                    <div style="width:64px;height:64px;border-radius:50%;background:#d1fae5;color:#059669;display:flex;align-items:center;justify-content:center;font-size:28px;margin:0 auto 1rem;">
                        <i class="fas fa-check"></i>
                    </div>
                    <h2 class="auth-title">Registration Complete</h2>
                    <div class="alert alert-success" style="text-align:left;"><i class="fas fa-info-circle"></i> <?php echo htmlspecialchars($success); ?></div>
                    <a href="login.php" class="btn btn-primary btn-block"><i class="fas fa-sign-in-alt"></i> Back to Login</a>
                </div>
            <?php else: ?>
                <h2 class="auth-title">Verify Your Email</h2>
                <p class="auth-subtitle">Enter the <?php echo OTP_LENGTH; ?>-digit code sent to your email to submit your registration for approval</p>
            <?php endif; ?>

            <?php if ($error): ?>
                <div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>

            <?php if (!empty($_SESSION['pending_registration'])): ?>
            <div class="alert alert-info" style="font-size:0.8125rem;">
                <i class="fas fa-envelope"></i> Email: <strong><?php echo htmlspecialchars($masked_email); ?></strong>
            </div>

            <form method="POST" action="" class="auth-form">
                <?php csrf_token_input(); ?>
                <div class="form-group">
                    <label for="otp"><i class="fas fa-key"></i> OTP Code</label>
                    <input type="text" id="otp" name="otp" class="form-control" placeholder="Enter <?php echo OTP_LENGTH; ?>-digit code" required maxlength="<?php echo OTP_LENGTH; ?>" pattern="\d{<?php echo OTP_LENGTH; ?>}" inputmode="numeric" autocomplete="one-time-code">
                </div>
                <button type="submit" class="btn btn-primary btn-block"><i class="fas fa-check"></i> Verify &amp; Submit for Approval</button>
            </form>

            <div class="auth-links">
                <form method="POST" action="" style="display:inline;">
                    <?php csrf_token_input(); ?>
                    <button type="submit" name="resend" value="1" id="resendLink" style="background:none;border:none;color:inherit;cursor:pointer;font:inherit;padding:0;"><i class="fas fa-redo"></i> Resend OTP</button>
                </form>
                <span id="resendTimer" style="display:none; color:var(--muted);"></span>
                <br>
                <a href="verify_registration_otp.php?cancel=1"><i class="fas fa-arrow-left"></i> Cancel registration</a>
            </div>
            <?php endif; ?>
        </div>
    </div>

    <?php require_once '../includes/footer.php'; ?>

    <?php if (!empty($_SESSION['pending_registration'])): ?>
    <script>
    (function () {
        var link = document.getElementById('resendLink');
        var timer = document.getElementById('resendTimer');
        var handle = null;
        var secondsLeft = <?php echo (int)$cooldown_left; ?>;

        function startCooldown(seconds) {
            if (handle) clearInterval(handle);
            if (seconds <= 0) { link.style.display = ''; timer.style.display = 'none'; return; }
            link.style.display = 'none';
            timer.style.display = 'inline';
            var endTime = Date.now() + (seconds * 1000);
            handle = setInterval(function () {
                var remaining = Math.max(0, Math.round((endTime - Date.now()) / 1000));
                if (remaining > 0) {
                    timer.textContent = 'Resend in ' + remaining + 's';
                } else {
                    clearInterval(handle);
                    handle = null;
                    timer.style.display = 'none';
                    link.style.display = '';
                }
            }, 1000);
            timer.textContent = 'Resend in ' + seconds + 's';
        }

        // Server-enforced cooldown (seconds) after the form POST reloads.
        startCooldown(secondsLeft);

        // After the resend POST lands, run the fresh cooldown client-side.
        <?php if ($success && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['resend']) && $error === ''): ?>
        startCooldown(<?php echo OTP_RESEND_COOLDOWN; ?>);
        <?php endif; ?>
    })();
    </script>
    <?php endif; ?>
</body>
</html>
