<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/csrf.php';

$via_otp = !empty($_SESSION['reset_verified_user_id']);
$security_verified = !empty($_SESSION['security_verified']);
$full_verified = $via_otp && $security_verified;
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
        html,body{height:100%;margin:0;padding:0;}
        body{overflow:auto;}
        .reset-wrapper{min-height:100vh;display:flex;flex-direction:column;}
        .reset-wrapper header{flex-shrink:0;}
        .reset-main{flex:1;display:flex;align-items:center;justify-content:center;padding:1rem;background:rgba(0,0,0,0.4);}
        .reset-card{background:var(--surface);border-radius:var(--radius-xl);box-shadow:var(--shadow-lg);width:100%;max-width:480px;border:1px solid var(--border);overflow:hidden;}
        .reset-card-header{text-align:center;padding:1.25rem 1.5rem 0.5rem;}
        .reset-card-header h2{font-size:1.25rem;margin:0;}
        .reset-card-header p{color:var(--text-light);font-size:0.8125rem;margin:0.25rem 0 0;}
        .step-ind{display:flex;justify-content:center;gap:0;padding:0.75rem 1.5rem 0;}
        .step-dot{display:flex;align-items:center;gap:0.5rem;font-size:0.8125rem;font-weight:500;color:var(--muted);}
        .step-dot.active{color:var(--primary);}
        .step-dot.completed{color:var(--success);}
        .step-dot .sn{width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:0.75rem;font-weight:600;background:var(--background);color:var(--muted);border:2px solid var(--border);}
        .step-dot.active .sn{background:var(--primary);color:white;border-color:var(--primary);}
        .step-dot.completed .sn{background:var(--success-bg);color:var(--success);border-color:var(--success);}
        .reset-body{padding:1rem 1.5rem;}
        .reset-step{display:none;}
        .reset-step.active{display:block;}
        .reset-step .form-group{margin-bottom:0.6rem;}
        .reset-step label{font-size:0.8125rem;font-weight:500;}
        .sq-card{background:var(--background);border-radius:var(--radius);padding:0.625rem 0.75rem;margin-bottom:0.5rem;border:1px solid var(--border);}
        .sq-card select,.sq-card input{height:32px;font-size:0.8125rem;}
        .reset-footer{padding:0 1.5rem 1rem;display:flex;gap:0.5rem;}
        .reset-footer .btn{flex:1;}
        .reset-links{text-align:center;padding:0.5rem 1.5rem 1rem;font-size:0.8125rem;color:var(--text-light);}
        .reset-links a{color:var(--primary);}
    </style>
</head>
<body style="background: url('../assets/homepage.jpg') center/cover no-repeat fixed; background-color: #1a1a2e;">
    <?php require_once '../includes/header_public.php'; ?>

    <div class="reset-wrapper">
        <main class="reset-main">
            <div class="reset-card">
                <div class="reset-card-header">
                    <h2><i class="fas fa-key" style="color:var(--primary);"></i> Reset Password</h2>
                    <p><?php echo $full_verified ? 'OTP and security questions verified. Set your new password.' : ($via_otp ? 'OTP verified. Set your new password.' : 'Answer your security questions to reset your password'); ?></p>
                </div>

                <?php if (!empty($_SESSION['reset_masked_id_number']) || !empty($_SESSION['reset_masked_email'])): ?>
                <div class="alert alert-info" style="margin:0.75rem 1.5rem 0;font-size:0.8125rem;display:flex;flex-direction:column;gap:0.25rem;">
                    <?php if (!empty($_SESSION['reset_masked_id_number'])): ?><span><i class="fas fa-id-card"></i> ID Number: <strong><?php echo htmlspecialchars($_SESSION['reset_masked_id_number']); ?></strong></span><?php endif; ?>
                    <?php if (!empty($_SESSION['reset_masked_email'])): ?><span><i class="fas fa-envelope"></i> Email: <strong><?php echo htmlspecialchars($_SESSION['reset_masked_email']); ?></strong></span><?php endif; ?>
                </div>
                <?php endif; ?>
                <?php if ($full_verified): ?>
                <div class="step-ind">
                    <div class="step-dot completed" id="si1"><div class="sn"><i class="fas fa-check" style="font-size:10px;"></i></div> OTP</div>
                    <div style="width:40px;height:2px;background:var(--success);margin:0 0.5rem;align-self:center;"></div>
                    <div class="step-dot completed" id="si2"><div class="sn"><i class="fas fa-check" style="font-size:10px;"></i></div> Security</div>
                    <div style="width:40px;height:2px;background:var(--success);margin:0 0.5rem;align-self:center;"></div>
                    <div class="step-dot active" id="si3"><div class="sn">3</div> New Password</div>
                </div>
                <?php elseif (!$via_otp): ?>
                <div class="step-ind">
                    <div class="step-dot active" id="si1"><div class="sn">1</div> Verify</div>
                    <div style="width:40px;height:2px;background:var(--border);margin:0 0.5rem;align-self:center;"></div>
                    <div class="step-dot" id="si2"><div class="sn">2</div> New Password</div>
                </div>
                <?php endif; ?>

                <div id="message" style="display:none;margin:0.5rem 1.5rem;"></div>

                <form id="resetForm">
                    <?php csrf_token_input(); ?>

                    <?php if (!$via_otp): ?>
                    <div class="reset-step active" id="step1">
                        <div class="reset-body">
                            <div class="form-group">
                                <label><i class="fas fa-user"></i> Username</label>
                                <input type="text" id="username" class="form-control" placeholder="Enter your username" required>
                            </div>

                            <div id="sqSection" style="display:none;margin-top:0.75rem;">
                                <p style="font-size:0.75rem;color:var(--text-light);margin-bottom:0.5rem;">Answer any ONE of your security questions:</p>
                                <div id="sqCards"></div>
                            </div>
                        </div>
                        <div class="reset-footer">
                            <a href="login.php" class="btn btn-outline"><i class="fas fa-arrow-left"></i> Back</a>
                            <button type="button" id="fetchBtn" class="btn btn-primary" onclick="fetchUser()"><i class="fas fa-arrow-right"></i> Fetch Details</button>
                            <button type="button" id="verifyBtn" class="btn btn-primary" style="display:none;" onclick="verifyAnswer()"><i class="fas fa-check"></i> Verify</button>
                        </div>
                    </div>
                    <?php endif; ?>

                    <div class="reset-step <?php echo $via_otp ? 'active' : ''; ?>" id="step2">
                        <div class="reset-body">
                            <div class="form-group">
                                <label><i class="fas fa-lock"></i> New Password</label>
                                <div style="position:relative;">
                                    <input type="password" id="new_password" class="form-control" required minlength="8" maxlength="30">
                                    <button type="button" onclick="togglePass('new_password',this)" style="position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;color:var(--muted);"><i class="fas fa-eye"></i></button>
                                </div>
                                <small id="passwordStrength" style="font-size:0.75rem;"></small>
                            </div>
                            <div class="form-group">
                                <label><i class="fas fa-lock"></i> Confirm New Password</label>
                                <div style="position:relative;">
                                    <input type="password" id="new_password_confirm" class="form-control" required>
                                    <button type="button" onclick="togglePass('new_password_confirm',this)" style="position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;color:var(--muted);"><i class="fas fa-eye"></i></button>
                                </div>
                                <small id="confirmStatus" style="font-size:0.75rem;"></small>
                            </div>
                        </div>
                        <div class="reset-footer">
                            <?php if ($full_verified): ?><a href="verify_security_after_otp.php" class="btn btn-outline"><i class="fas fa-arrow-left"></i> Back</a><?php elseif (!$via_otp): ?><button type="button" class="btn btn-outline" onclick="goToStep(1)"><i class="fas fa-arrow-left"></i> Back</button><?php endif; ?>
                            <button type="submit" class="btn btn-success" style="<?php echo $full_verified ? 'width:100%' : ''; ?>"><i class="fas fa-check"></i> Reset Password</button>
                        </div>
                    </div>
                </form>

                <div class="reset-links"><a href="login.php"><i class="fas fa-arrow-left"></i> Back to Login</a></div>
            </div>
        </main>
        <footer style="flex-shrink:0;padding:0.5rem;text-align:center;color:rgba(255,255,255,0.7);font-size:0.75rem;border:none;"><p style="margin:0;padding:0;border:none;">&copy; <?php echo date('Y'); ?> MovieHub. All rights reserved.</p></footer>
    </div>

    <script>
    let securityQuestions = [];
    let verifiedQuestionId = -1;
    let verifiedUsername = '';
    const viaOtp = <?php echo $via_otp ? 'true' : 'false'; ?>;

    function showMsg(msg, isError) {
        const el = document.getElementById('message');
        el.textContent = msg;
        el.className = isError ? 'alert alert-danger' : 'alert alert-success';
        el.style.display = 'block';
        setTimeout(() => el.style.display = 'none', 5000);
    }

    function goToStep(step) {
        document.querySelectorAll('.reset-step').forEach(s => s.classList.remove('active'));
        document.querySelectorAll('.step-dot').forEach(s => { s.classList.remove('active','completed'); });
        document.getElementById('step'+step).classList.add('active');
        document.getElementById('si'+step).classList.add('active');
        if (step === 2) document.getElementById('si1').classList.add('completed');
    }

    function togglePass(id, btn) {
        const inp = document.getElementById(id);
        const isPwd = inp.type === 'password';
        inp.type = isPwd ? 'text' : 'password';
        btn.querySelector('i').classList.toggle('fa-eye');
        btn.querySelector('i').classList.toggle('fa-eye-slash');
    }

    function toggleSq(btn) {
        const inp = btn.previousElementSibling;
        const isPwd = inp.type === 'password';
        inp.type = isPwd ? 'text' : 'password';
        btn.querySelector('i').classList.toggle('fa-eye');
        btn.querySelector('i').classList.toggle('fa-eye-slash');
    }

    async function fetchUser() {
        const username = document.getElementById('username').value.trim();
        if (!username) { showMsg('Please enter your username.', true); return; }

        try {
            const r = await fetch('get_security_question.php', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: 'username=' + encodeURIComponent(username)
            });
            const data = await r.json();
            if (!data.ok) { showMsg(data.message || 'Username not found.', true); return; }

            securityQuestions = data.security_questions || [];
            verifiedUsername = username;

            const container = document.getElementById('sqCards');
            container.innerHTML = '';
            securityQuestions.forEach((sq, i) => {
                const card = document.createElement('div');
                card.className = 'sq-card';
                card.innerHTML = '<label style="font-size:0.75rem;font-weight:600;margin-bottom:0.25rem;"><i class="fas fa-shield-alt" style="color:var(--primary);"></i> ' + sq.question + '</label>' +
                    '<div style="position:relative;"><input type="password" id="sa_' + sq.id + '" class="form-control" placeholder="Your answer" style="margin-top:0.25rem;padding-right:2.5rem;"><button type="button" onclick="toggleSq(this)" style="position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;color:var(--muted);"><i class="fas fa-eye"></i></button></div>';
                container.appendChild(card);
            });

            document.getElementById('sqSection').style.display = 'block';
            document.getElementById('username').readOnly = true;
            document.getElementById('fetchBtn').style.display = 'none';
            document.getElementById('verifyBtn').style.display = 'inline-block';
        } catch (e) {
            showMsg('An error occurred. Please try again.', true);
        }
    }

    async function verifyAnswer() {
        let matchedId = -1;
        let matchedAnswer = '';

        for (let i = 0; i < securityQuestions.length; i++) {
            const val = document.getElementById('sa_' + securityQuestions[i].id).value.trim();
            if (val) { matchedId = securityQuestions[i].id; matchedAnswer = val; break; }
        }

        if (matchedId === -1) {
            showMsg('Please answer at least one security question.', true);
            return;
        }

        try {
            const params = new URLSearchParams();
            params.append('username', verifiedUsername);
            params.append('security_answer', matchedAnswer);
            params.append('question_id', matchedId);

            const r = await fetch('verify_security_answer.php', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: params.toString()
            });
            const data = await r.json();

            if (data.ok) {
                verifiedQuestionId = matchedId;
                goToStep(2);
            } else {
                showMsg(data.message || 'Incorrect answer.', true);
            }
        } catch (e) {
            showMsg('An error occurred. Please try again.', true);
        }
    }

    document.getElementById('resetForm').addEventListener('submit', async function(e) {
        e.preventDefault();
        const pw = document.getElementById('new_password').value;
        const cpw = document.getElementById('new_password_confirm').value;
        const csrfToken = document.querySelector('input[name="csrf_token"]').value;

        if (pw !== cpw) { showMsg('Passwords do not match.', true); return; }
        if (pw.length < 8 || pw.length > 30) { showMsg('Password must be 8-30 characters.', true); return; }

        const formData = new FormData();
        formData.append('csrf_token', csrfToken);
        formData.append('new_password', pw);
        formData.append('new_password_confirm', cpw);

        if (viaOtp) {
            formData.append('via_otp', '1');
        } else {
            formData.append('username', verifiedUsername);
            formData.append('question_id', verifiedQuestionId);
            const ansEl = document.getElementById('sa_' + verifiedQuestionId);
            if (ansEl) formData.append('security_answer', ansEl.value.trim());
        }

        try {
            const r = await fetch('reset_password.php', { method: 'POST', body: formData });
            const data = await r.json();
            if (data.ok) {
                showMsg(data.message || 'Password reset successful!', false);
                setTimeout(() => window.location.href = 'login.php', 2000);
            } else {
                showMsg(data.message || 'Failed to reset.', true);
            }
        } catch (e) {
            showMsg('An error occurred. Please try again.', true);
        }
    });

    document.getElementById('new_password').addEventListener('input', function() {
        const p = this.value;
        const meter = document.getElementById('passwordStrength');
        let score = 0;
        if (p.length >= 8) score++;
        if (/[a-z]/.test(p) && /[A-Z]/.test(p)) score++;
        if (/\d/.test(p)) score++;
        if (/[^A-Za-z0-9]/.test(p)) score++;
        const labels = ['Weak','Medium','Strong','Very Strong'];
        const colors = ['var(--danger)','var(--warning)','var(--success)','var(--success)'];
        if (p.length > 0) { meter.textContent = labels[Math.max(0,score-1)]; meter.style.color = colors[Math.max(0,score-1)]; }
        else { meter.textContent = ''; }
        checkConfirm();
    });

    function checkConfirm() {
        const ok = document.getElementById('new_password').value === document.getElementById('new_password_confirm').value && document.getElementById('new_password_confirm').value.length > 0;
        const s = document.getElementById('confirmStatus');
        s.textContent = document.getElementById('new_password_confirm').value ? (ok ? 'Passwords match' : 'Passwords do not match') : '';
        s.style.color = ok ? 'var(--success)' : 'var(--danger)';
    }
    document.getElementById('new_password_confirm').addEventListener('input', checkConfirm);
    </script>
</body>
</html>
