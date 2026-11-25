<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/authorization.php';
require_once '../includes/csrf.php';

require_login();

$new_user_setup = !empty($_SESSION['pending_user_setup']);

if (!isset($_SESSION['user_id']) && !$new_user_setup) {
    if (isset($_SESSION['admin_id'])) {
        header('Location: ../admin/change_password.php');
    } else {
        header('Location: login.php');
    }
    exit();
}

$setup_required = $new_user_setup ? true : !empty($_SESSION['must_change_password']);

$secret_questions = [];
try {
    $stmt = $pdo->query("SELECT id, question_text FROM secret_questions WHERE is_active = 1 AND id IN (1, 2, 3) ORDER BY sort_order, id");
    $secret_questions = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $secret_questions = [];
}

$existing_security = [];
try {
    $stmt = $pdo->prepare("SELECT question_id FROM security_answers WHERE user_table = 'users' AND user_id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $existing_security = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $existing_security = [];
}

$success = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token. Please try again.';
    } else {
        $new_password = $_POST['new_password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';
        $sq_ids = [(int)($_POST['sq1_id'] ?? 0), (int)($_POST['sq2_id'] ?? 0), (int)($_POST['sq3_id'] ?? 0)];
        $sq_answers = [trim($_POST['sa1'] ?? ''), trim($_POST['sa2'] ?? ''), trim($_POST['sa3'] ?? '')];

        if (strlen($new_password) < 8 || strlen($new_password) > 30) {
            $error = 'Password must be 8-30 characters.';
        } elseif ($new_password !== $confirm_password) {
            $error = 'Passwords do not match.';
        } elseif ($setup_required && (in_array(0, $sq_ids, true) || in_array('', $sq_answers, true))) {
            $error = 'Please set all 3 security questions and answers to complete your account setup.';
        } elseif ($setup_required && count(array_unique($sq_ids)) !== 3) {
            $error = 'Security questions must be different.';
        } elseif (count(array_filter($sq_ids, function ($v) { return $v > 0; })) === 3 && count(array_unique($sq_ids)) !== 3) {
            $error = 'Security questions must be different.';
        } elseif (($setup_required || count(array_filter($sq_ids, function ($v) { return $v > 0; })) === 3) && !security_question_ids_are_valid($pdo, $sq_ids)) {
            $error = 'Choose three different active security questions.';
        } else {
            try {
                $pdo->beginTransaction();
                $hashed = password_hash($new_password, PASSWORD_DEFAULT);
                if ($new_user_setup) {
                    $pd = $_SESSION['pending_user_data'] ?? [];
                    $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ? OR email = ? OR id_number = ?");
                    $stmt->execute([$pd['username'] ?? '', $pd['email'] ?? '', $pd['id_number'] ?? '']);
                    if ($stmt->fetch()) {
                        throw new RuntimeException('This username, email, or ID number is already in use. Contact the Super Administrator.');
                    }
                    $stmt = $pdo->prepare("INSERT INTO users (id_number, username, email, password, role, account_status, must_change_password, first_name, last_name, sex, birthdate, contact_number, security_question, security_answer_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
                    $stmt->execute([
                        $pd['id_number'] ?? null, $pd['username'], $pd['email'], $hashed,
                        'user', STATUS_APPROVED, 0, null, null, null, null, null, null, null
                    ]);
                    $new_user_id = $pdo->lastInsertId();

                    $ins = $pdo->prepare("INSERT INTO security_answers (user_table, user_id, question_id, answer_hash) VALUES ('users', ?, ?, ?)");
                    for ($i = 0; $i < 3; $i++) {
                        $answer_hash = password_hash(strtolower(trim($sq_answers[$i])), PASSWORD_DEFAULT);
                        $ins->execute([$new_user_id, $sq_ids[$i], $answer_hash]);
                    }

                    $del = $pdo->prepare("DELETE FROM pending_user_accounts WHERE username = ?");
                    $del->execute([$pd['username']]);

                    $_SESSION['user_id'] = $new_user_id;
                    $_SESSION['username'] = $pd['username'];
                    $_SESSION['full_name'] = '';
                    $_SESSION['email'] = $pd['email'];
                    $_SESSION['user_role'] = 'user';
                    $_SESSION['account_status'] = STATUS_APPROVED;
                    $_SESSION['id_number'] = $pd['id_number'] ?? null;
                    unset($_SESSION['pending_user_setup'], $_SESSION['pending_user_data']);
                    log_audit($pdo, 'register', 'users', $new_user_id, $pd['username'], 'User account activated (first-login setup)');
                } else {
                    $stmt = $pdo->prepare("UPDATE users SET password = ?, must_change_password = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?");
                    $stmt->execute([$hashed, $_SESSION['user_id']]);

                    if (count(array_filter($sq_ids, function ($v) { return $v > 0; })) === 3 && !in_array('', $sq_answers, true)) {
                        $del = $pdo->prepare("DELETE FROM security_answers WHERE user_table = 'users' AND user_id = ?");
                        $del->execute([$_SESSION['user_id']]);
                        $ins = $pdo->prepare("INSERT INTO security_answers (user_table, user_id, question_id, answer_hash) VALUES ('users', ?, ?, ?)");
                        for ($i = 0; $i < 3; $i++) {
                            $answer_hash = password_hash(strtolower(trim($sq_answers[$i])), PASSWORD_DEFAULT);
                            $ins->execute([$_SESSION['user_id'], $sq_ids[$i], $answer_hash]);
                        }
                    }
                }

                $pdo->commit();
                $_SESSION['must_change_password'] = 0;
                log_audit($pdo, 'password_change', 'users', $_SESSION['user_id'], $_SESSION['full_name'] ?? '', 'Password changed' . ($setup_required ? ' (forced setup)' : ''));
                $success = $new_user_setup ? 'Your account has been activated. Redirecting to your dashboard...' : 'Password changed successfully. Redirecting to your dashboard...';
                $redirect_after = 'dashboard.php';
            } catch (PDOException $e) {
                if ($pdo->inTransaction()) { $pdo->rollBack(); }
                error_log('[client/change_password] ' . $e->getMessage());
                $error = $new_user_setup ? 'Failed to activate your account. Please try again.' : 'Failed to update your password. Please try again.';
            } catch (RuntimeException $e) {
                if ($pdo->inTransaction()) { $pdo->rollBack(); }
                $error = $e->getMessage();
            }
        }
    }
}
generate_csrf_token();
$existing_qids = array_column($existing_security, 'question_id');
$has_security = count($existing_qids) >= 3;
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
        .cp-card { background:rgba(18,24,38,0.95); backdrop-filter:blur(16px); border-radius:var(--radius-xl); box-shadow:0 20px 60px rgba(0,0,0,0.5); width:100%; max-width:560px; border:1px solid var(--border-dark); padding:2rem; }
        .pw-toggle { position:absolute; right:12px; top:50%; transform:translateY(-50%); background:none; border:none; cursor:pointer; color:var(--text-light); font-size:1rem; }
        .password-wrapper { position:relative; } .password-wrapper .form-control { padding-right:40px; }
        .sq-item { background:var(--background); border-radius:var(--radius); padding:0.5rem 0.75rem; margin-bottom:0.65rem; }
    </style>
</head>
<body>
    <div class="cp-wrapper">
        <div class="cp-card">
            <div class="auth-logo"><i class="fas fa-key"></i><h1>MovieHub</h1></div>
            <h2 class="auth-title"><?php echo $new_user_setup ? 'Account Setup' : 'Change Password'; ?></h2>
            <p class="auth-subtitle"><?php echo $new_user_setup ? 'Set your new password and security questions to activate your account.' : ($setup_required ? 'Your password was recently changed by an administrator. Complete your account setup below.' : 'Update your password and, optionally, your security questions.'); ?></p>

            <?php if ($new_user_setup): ?>
            <div class="alert alert-warning" style="margin-top:1rem;font-size:0.875rem;">
                <i class="fas fa-exclamation-triangle"></i>
                <span style="flex:1;min-width:0;"><strong>Notice:</strong> Your account is not yet stored in the database. It will be created only after you set your <strong>new password</strong> and <strong>security questions</strong>.</span>
            </div>
            <?php elseif ($setup_required): ?>
            <div class="alert alert-warning" style="margin-top:1rem;font-size:0.875rem;">
                <i class="fas fa-exclamation-triangle"></i>
                <span style="flex:1;min-width:0;"><strong>Notice:</strong> Your password was changed by a Super Administrator. For security, you are required to <strong>change your password</strong> and <strong>set your security questions</strong> before continuing.</span>
            </div>
            <?php endif; ?>

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

                <div class="card" style="background:var(--surface-2);border:1px dashed var(--border);margin-top:1.25rem;">
                    <div class="card-body">
                        <label style="font-weight:700;font-size:0.8125rem;color:var(--text);display:block;margin-bottom:0.25rem;"><i class="fas fa-shield-alt" style="color:var(--primary);"></i> Security Question Setup</label>
                        <small style="display:block;color:var(--text-light);font-size:0.75rem;margin-bottom:0.75rem;"><?php echo $setup_required ? 'Required to finish your account setup.' : 'Select 3 different questions. Leave blank to keep your current questions.'; ?></small>
                        <?php for ($i = 0; $i < 3; $i++): ?>
                            <div class="sq-item">
                                <label style="font-size:0.75rem;font-weight:600;display:block;margin-bottom:0.25rem;">Security Question <?php echo $i + 1; ?> <?php echo $setup_required ? '*' : ''; ?></label>
                                <select name="sq<?php echo $i + 1; ?>_id" class="form-control sq-select" data-idx="<?php echo $i; ?>" <?php echo $setup_required ? 'required' : ''; ?>>
                                    <option value="0" <?php echo $setup_required ? '' : 'selected'; ?>>-- <?php echo $setup_required ? 'Select a question' : 'Keep existing question'; ?> --</option>
                                    <?php foreach ($secret_questions as $q): ?>
                                        <option value="<?php echo $q['id']; ?>" <?php echo (isset($existing_qids[$i]) && (int)$existing_qids[$i] === (int)$q['id']) ? 'selected' : ''; ?>><?php echo htmlspecialchars($q['question_text']); ?></option>
                                    <?php endforeach; ?>
                                </select>
                                <input type="text" name="sa<?php echo $i + 1; ?>" class="form-control" placeholder="<?php echo $setup_required ? 'Your answer' : ($has_security ? 'Answer (blank keeps current)' : 'Your answer'); ?>" autocomplete="off" style="margin-top:0.4rem;" <?php echo $setup_required ? 'required' : ''; ?>>
                            </div>
                        <?php endfor; ?>
                        <?php if (!$setup_required): ?>
                            <small style="font-size:0.6875rem;color:var(--muted);">To update security questions, select 3 different questions and fill in their answers.</small>
                        <?php endif; ?>
                    </div>
                </div>

                <button type="submit" class="btn btn-primary btn-block" style="margin-top:1.25rem;"><i class="fas fa-check"></i> <?php echo $setup_required ? 'Complete Setup' : 'Change Password'; ?></button>
            </form>
            <div class="auth-links" style="text-align:center;margin-top:1rem;">
                <a href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a>
                <?php if (!$setup_required): ?> &nbsp;|&nbsp; <a href="dashboard.php"><i class="fas fa-tachometer-alt"></i> Skip for now</a><?php endif; ?>
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

    (function () {
        var selects = document.getElementsByClassName('sq-select');
        function refresh() {
            var selectedQuestions = {};
            for (var i = 0; i < selects.length; i++) {
                if (selects[i].value !== '0') selectedQuestions[selects[i].value] = true;
            }
            for (var i = 0; i < selects.length; i++) {
                for (var j = 0; j < selects[i].options.length; j++) {
                    var option = selects[i].options[j];
                    option.disabled = option.value !== '0' && selectedQuestions[option.value] === true && option.value !== selects[i].value;
                }
            }
        }
        for (var i = 0; i < selects.length; i++) {
            selects[i].addEventListener('change', refresh);
        }
        refresh();
    })();
    </script>
</body>
</html>
