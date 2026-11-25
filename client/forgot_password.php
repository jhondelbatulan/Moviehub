<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/otp.php';
require_once '../includes/csrf.php';

if (isset($_SESSION['user_id'])) { header('Location: dashboard.php'); exit(); }

$error = '';
$success = '';
$masked_email = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token. Please try again.';
    } else {
        $id_number = trim($_POST['id_number'] ?? '');
        unset($_SESSION['reset_masked_id_number'], $_SESSION['reset_masked_email']);
        if ($id_number === '') {
            $error = 'Please enter your ID number.';
        } elseif (!preg_match('/^\d{4}-\d{4}$/', $id_number)) {
            $error = 'ID number must be in the format xxxx-xxxx (e.g. 1234-5678).';
        } else {
            try {
                $user = null;
                $user_table = '';
                $full_name = '';
                $stmt = $pdo->prepare("SELECT id, email, CONCAT(first_name, ' ', last_name) AS full_name FROM users WHERE id_number = ? AND is_deleted = 0");
                $stmt->execute([$id_number]);
                $found = $stmt->fetch();
                if ($found) {
                    $user = $found;
                    $user_table = 'users';
                    $full_name = $found['full_name'];
                } else {
                    $stmt = $pdo->prepare("SELECT id, email, full_name FROM admin_users WHERE id_number = ? AND is_deleted = 0");
                    $stmt->execute([$id_number]);
                    $found = $stmt->fetch();
                    if ($found) {
                        $user = $found;
                        $user_table = 'admin_users';
                        $full_name = $found['full_name'];
                    }
                }
                if (!$user) {
                    $error = 'ID number doesn\'t exist.';
                } else {
                    $_SESSION['reset_masked_id_number'] = mask_id_number($id_number);
                    $_SESSION['reset_masked_email'] = mask_email($user['email']);
                    if (!can_resend_otp($pdo, $user_table, $user['id'], 'password_reset')) {
                        $error = 'Too many OTP requests. Please wait before trying again.';
                    } else {
                        $otp = create_otp($pdo, $user_table, $user['id'], 'password_reset');
                        $_SESSION['otp_user_id'] = $user['id'];
                        $_SESSION['otp_user_table'] = $user_table;
                        $_SESSION['otp_purpose'] = 'password_reset';
                        $_SESSION['otp_masked_id_number'] = $_SESSION['reset_masked_id_number'];
                        $_SESSION['otp_masked_email'] = $_SESSION['reset_masked_email'];
                        send_otp_email($user['email'], $otp, $full_name);
                        $masked_email = mask_email($user['email']);
                        $success = 'An OTP has been sent to your registered email (' . $masked_email . ').';
                        header('Location: verify_otp.php');
                        exit();
                    }
                }
            } catch (PDOException $e) {
                error_log('[forgot_password] '.$e->getMessage());
                $error = 'A system error occurred. Please try again.';
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
    <title>Forgot Password - MovieHub</title>
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
            <h2 class="auth-title">Forgot Password</h2>
            <p class="auth-subtitle">Enter your ID number to receive a reset code</p>

            <?php if ($error): ?>
                <div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            <?php if ($success): ?>
                <div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($success); ?></div>
            <?php endif; ?>

            <form method="POST" action="" class="auth-form">
                <?php csrf_token_input(); ?>
                <div class="form-group">
                    <label for="id_number"><i class="fas fa-id-card"></i> ID Number</label>
                    <div class="password-wrapper" style="position:relative;">
                        <input type="password" id="id_number" name="id_number" class="form-control" placeholder="Enter your ID number (xxxx-xxxx)" required maxlength="9" autocomplete="off" inputmode="numeric" style="padding-right:2.5rem;">
                        <button type="button" onclick="toggleIdNumber(this)" style="position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;color:var(--muted);"><i class="fas fa-eye"></i></button>
                    </div>
                    <small style="font-size:0.75rem;color:var(--text-light);">The one-time code will be sent to the email registered to this ID number.</small>
                </div>
                <button type="submit" class="btn btn-primary btn-block"><i class="fas fa-paper-plane"></i> Send OTP</button>
            </form>

            <div class="auth-links">
                <a href="login.php"><i class="fas fa-arrow-left"></i> Back to Login</a>
            </div>
        </div>
    </div>

    <?php require_once '../includes/footer.php'; ?>

    <script>
    function toggleIdNumber(btn) {
        var inp = btn.previousElementSibling;
        var isPwd = inp.type === 'password';
        inp.type = isPwd ? 'text' : 'password';
        btn.querySelector('i').classList.toggle('fa-eye');
        btn.querySelector('i').classList.toggle('fa-eye-slash');
    }
    document.getElementById('id_number').addEventListener('input', function (e) {
        var v = e.target.value.replace(/[^\d-]/g, '');
        var d = v.replace(/-/g, '');
        if (d.length > 4) v = d.substring(0, 4) + '-' + d.substring(4, 8);
        else v = d;
        e.target.value = v;
    });
    </script>
</body>
</html>
