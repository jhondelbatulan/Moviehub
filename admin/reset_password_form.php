<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/csrf.php';

if (empty($_SESSION['reset_verified_user_id'])) {
    header('Location: forgot_password.php');
    exit();
}

generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password - MovieHub</title>
    <link rel="stylesheet" href="../assets/css/style.css?v=2.3.0">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        .pw-toggle { position:absolute; right:12px; top:50%; transform:translateY(-50%); background:none; border:none; cursor:pointer; color:var(--muted); font-size:1rem; }
        .password-wrapper { position:relative; } .password-wrapper .form-control { padding-right:40px; }
    </style>
</head>
<body style="background: url('../assets/homepage.jpg') center/cover no-repeat fixed; background-color: #1a1a2e;">
    <?php require_once '../includes/header_public.php'; ?>

    <div class="auth-wrapper">
        <div class="auth-card">
            <div class="auth-logo"><i class="fas fa-cog"></i><h1>MovieHub</h1></div>
            <h2 class="auth-title">Reset Password</h2>
            <p class="auth-subtitle">OTP verified. Set your new password.</p>

            <div id="message" style="display:none;"></div>

            <form id="resetForm" class="auth-form" onsubmit="return false;">
                <?php csrf_token_input(); ?>
                <div class="form-group">
                    <label for="new_password"><i class="fas fa-lock"></i> New Password</label>
                    <div class="password-wrapper">
                        <input type="password" id="new_password" class="form-control" required minlength="8" maxlength="30" autocomplete="new-password">
                        <button type="button" class="pw-toggle" onclick="togglePass('new_password',this)" tabindex="-1"><i class="fas fa-eye"></i></button>
                    </div>
                    <small id="passwordStrength" style="font-size:0.75rem;"></small>
                </div>
                <div class="form-group">
                    <label for="new_password_confirm"><i class="fas fa-lock"></i> Confirm New Password</label>
                    <div class="password-wrapper">
                        <input type="password" id="new_password_confirm" class="form-control" required autocomplete="new-password">
                        <button type="button" class="pw-toggle" onclick="togglePass('new_password_confirm',this)" tabindex="-1"><i class="fas fa-eye"></i></button>
                    </div>
                    <small id="confirmStatus" style="font-size:0.75rem;"></small>
                </div>
                <button type="submit" class="btn btn-success btn-block"><i class="fas fa-check"></i> Reset Password</button>
            </form>

            <div class="auth-links">
                <a href="login.php"><i class="fas fa-arrow-left"></i> Back to Admin Login</a>
            </div>
        </div>
    </div>

    <?php require_once '../includes/footer.php'; ?>

    <script>
    function togglePass(id, btn) {
        var inp = document.getElementById(id);
        var isPwd = inp.type === 'password';
        inp.type = isPwd ? 'text' : 'password';
        btn.querySelector('i').classList.toggle('fa-eye');
        btn.querySelector('i').classList.toggle('fa-eye-slash');
    }
    function showMsg(msg, isError) {
        var el = document.getElementById('message');
        el.textContent = msg;
        el.className = isError ? 'alert alert-danger' : 'alert alert-success';
        el.style.display = 'block';
    }
    function checkConfirm() {
        var ok = document.getElementById('new_password').value === document.getElementById('new_password_confirm').value && document.getElementById('new_password_confirm').value.length > 0;
        var s = document.getElementById('confirmStatus');
        s.textContent = document.getElementById('new_password_confirm').value ? (ok ? 'Passwords match' : 'Passwords do not match') : '';
        s.style.color = ok ? 'var(--success)' : 'var(--danger)';
    }
    document.getElementById('new_password').addEventListener('input', function() {
        var p = this.value, meter = document.getElementById('passwordStrength'), score = 0;
        if (p.length >= 8) score++;
        if (/[a-z]/.test(p) && /[A-Z]/.test(p)) score++;
        if (/\d/.test(p)) score++;
        if (/[^A-Za-z0-9]/.test(p)) score++;
        var labels = ['Weak','Medium','Strong','Very Strong'], colors = ['var(--danger)','var(--warning)','var(--success)','var(--success)'];
        if (p.length > 0) { meter.textContent = labels[Math.max(0,score-1)]; meter.style.color = colors[Math.max(0,score-1)]; } else { meter.textContent = ''; }
        checkConfirm();
    });
    document.getElementById('new_password_confirm').addEventListener('input', checkConfirm);
    document.getElementById('resetForm').addEventListener('submit', async function(e) {
        e.preventDefault();
        var pw = document.getElementById('new_password').value;
        var cpw = document.getElementById('new_password_confirm').value;
        var csrfToken = document.querySelector('input[name="csrf_token"]').value;
        if (pw.length < 8 || pw.length > 30) { showMsg('Password must be 8-30 characters.', true); return; }
        if (pw !== cpw) { showMsg('Passwords do not match.', true); return; }
        var fd = new FormData();
        fd.append('csrf_token', csrfToken);
        fd.append('new_password', pw);
        fd.append('new_password_confirm', cpw);
        try {
            var r = await fetch('reset_password.php', { method: 'POST', body: fd });
            var data = await r.json();
            if (data.ok) {
                showMsg(data.message || 'Password reset successful!', false);
                setTimeout(function(){ window.location.href = 'login.php'; }, 1500);
            } else {
                showMsg(data.message || 'Failed to reset.', true);
            }
        } catch(e) { showMsg('An error occurred. Please try again.', true); }
    });
    </script>
</body>
</html>
