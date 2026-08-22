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

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token. Please try again.';
    } else {
        $email = trim($_POST['email'] ?? '');
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = 'Please enter a valid email address.';
        } else {
            try {
                $stmt = $pdo->prepare("SELECT id, email, CONCAT(first_name, ' ', last_name) as full_name FROM users WHERE email = ? AND is_deleted = 0");
                $stmt->execute([$email]);
                $user = $stmt->fetch();
                if (!$user) {
                    $success = 'If an account with that email exists, an OTP has been sent.';
                } else {
                    if (!can_resend_otp($pdo, 'users', $user['id'], 'password_reset')) {
                        $error = 'Too many OTP requests. Please wait before trying again.';
                    } else {
                        $otp = create_otp($pdo, 'users', $user['id'], 'password_reset');
                        $_SESSION['otp_user_id'] = $user['id'];
                        $_SESSION['otp_purpose'] = 'password_reset';
                        send_otp_email($user['email'], $otp, $user['full_name']);
                        $success = 'An OTP has been sent to your email. It will expire in ' . OTP_EXPIRY_MINUTES . ' minutes.';
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
            <p class="auth-subtitle">Enter your email to receive a reset code</p>

            <?php if ($error): ?>
                <div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            <?php if ($success): ?>
                <div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($success); ?></div>
            <?php endif; ?>

            <form method="POST" action="" class="auth-form">
                <?php csrf_token_input(); ?>
                <div class="form-group">
                    <label for="email"><i class="fas fa-envelope"></i> Email Address</label>
                    <input type="email" id="email" name="email" class="form-control" placeholder="Enter your registered email" required>
                </div>
                <button type="submit" class="btn btn-primary btn-block"><i class="fas fa-paper-plane"></i> Send OTP</button>
            </form>

            <div class="auth-links">
                <a href="login.php"><i class="fas fa-arrow-left"></i> Back to Login</a>
            </div>
        </div>
    </div>

    <?php require_once '../includes/footer.php'; ?>
</body>
</html>
