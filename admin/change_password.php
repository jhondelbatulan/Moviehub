<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/authorization.php';
require_once '../includes/csrf.php';

require_login();

$new_account_setup = !empty($_SESSION['pending_admin_setup']);

if (!isset($_SESSION['admin_id']) && !$new_account_setup) {
    header('Location: login.php');
    exit();
}

$setup_required = $new_account_setup ? true : !empty($_SESSION['must_change_password']);

$secret_questions = [];
try {
    $stmt = $pdo->query("SELECT id, question_text FROM secret_questions WHERE is_active = 1 AND id IN (1, 2, 3) ORDER BY sort_order, id");
    $secret_questions = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $secret_questions = [];
}

$existing_security = [];
try {
    if (isset($_SESSION['admin_id'])) {
        $stmt = $pdo->prepare("SELECT question_id FROM security_answers WHERE user_table = 'admin_users' AND user_id = ?");
        $stmt->execute([$_SESSION['admin_id']]);
        $existing_security = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
} catch (PDOException $e) {
    $existing_security = [];
}

$success = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token. Please try again.';
    } else {
        $first_name = trim($_POST['first_name'] ?? '');
        $middle_name = trim($_POST['middle_name'] ?? '');
        $last_name = trim($_POST['last_name'] ?? '');
        $new_password = $_POST['new_password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';
        $sq_ids = [(int)($_POST['sq1_id'] ?? 0), (int)($_POST['sq2_id'] ?? 0), (int)($_POST['sq3_id'] ?? 0)];
        $sq_answers = [trim($_POST['sa1'] ?? ''), trim($_POST['sa2'] ?? ''), trim($_POST['sa3'] ?? '')];

        if ($new_account_setup && $first_name === '') {
            $error = 'First name is required.';
        } elseif ($new_account_setup && ($name_error = validate_name_field($first_name)) !== '') {
            $error = 'First name: ' . $name_error;
        } elseif ($new_account_setup && $last_name === '') {
            $error = 'Last name is required.';
        } elseif ($new_account_setup && ($name_error = validate_name_field($last_name)) !== '') {
            $error = 'Last name: ' . $name_error;
        } elseif ($new_account_setup && $middle_name !== '' && !preg_match('/^[A-Z]$/', $middle_name)) {
            $error = 'Middle name initial must be one capital letter.';
        } elseif (($password_error = validate_strong_password($new_password)) !== '') {
            $error = $password_error;
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
                if ($new_account_setup) {
                    $pd = $_SESSION['pending_admin_data'] ?? [];
                    $full_name = trim($first_name . ' ' . ($middle_name !== '' ? $middle_name . ' ' : '') . $last_name);
                    $new_role = in_array(($pd['role'] ?? ''), ['admin', 'super_admin'], true) ? $pd['role'] : 'admin';
                    $stmt = $pdo->prepare("SELECT id FROM admin_users WHERE username = ? OR email = ? OR id_number = ?");
                    $stmt->execute([$pd['username'] ?? '', $pd['email'] ?? '', $pd['id_number'] ?? '']);
                    if ($stmt->fetch()) {
                        throw new RuntimeException('This username, email, or ID number is already in use. Contact the Super Administrator.');
                    }
                    $stmt = $pdo->prepare("INSERT INTO admin_users (username, email, password, full_name, first_name, middle_initial, last_name, role, account_status, id_number, phone, must_change_password) VALUES (?,?,?,?,?,?,?,?, 'active', ?, ?, 0)");
                    $stmt->execute([
                        $pd['username'], $pd['email'], $hashed, $full_name, $first_name,
                        $middle_name !== '' ? $middle_name : null,
                        $last_name, $new_role, $pd['id_number'] ?? null, $pd['phone'] ?? null
                    ]);
                    $new_admin_id = $pdo->lastInsertId();

                    // The new staff member takes the active seat for their role.
                    deactivate_same_role_admins($pdo, $new_admin_id, $new_role, $full_name);

                    $ins = $pdo->prepare("INSERT INTO security_answers (user_table, user_id, question_id, answer_hash) VALUES ('admin_users', ?, ?, ?)");
                    for ($i = 0; $i < 3; $i++) {
                        $answer_hash = password_hash(strtolower(trim($sq_answers[$i])), PASSWORD_DEFAULT);
                        $ins->execute([$new_admin_id, $sq_ids[$i], $answer_hash]);
                    }

                    $del = $pdo->prepare("DELETE FROM pending_admin_accounts WHERE username = ?");
                    $del->execute([$pd['username']]);
                    $setup_name = $full_name;
                } else {
                    $stmt = $pdo->prepare("UPDATE admin_users SET password = ?, must_change_password = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?");
                    $stmt->execute([$hashed, $_SESSION['admin_id']]);

                    if (count(array_filter($sq_ids, function ($v) { return $v > 0; })) === 3 && !in_array('', $sq_answers, true)) {
                        $del = $pdo->prepare("DELETE FROM security_answers WHERE user_table = 'admin_users' AND user_id = ?");
                        $del->execute([$_SESSION['admin_id']]);
                        $ins = $pdo->prepare("INSERT INTO security_answers (user_table, user_id, question_id, answer_hash) VALUES ('admin_users', ?, ?, ?)");
                        for ($i = 0; $i < 3; $i++) {
                            $answer_hash = password_hash(strtolower(trim($sq_answers[$i])), PASSWORD_DEFAULT);
                            $ins->execute([$_SESSION['admin_id'], $sq_ids[$i], $answer_hash]);
                        }
                    }
                }

                $pdo->commit();
                if ($new_account_setup) {
                    unset($_SESSION['pending_admin_setup'], $_SESSION['pending_admin_data']);
                    session_regenerate_id(true);
                    $_SESSION['admin_id'] = (int)$new_admin_id;
                    $_SESSION['admin_username'] = $pd['username'];
                    $_SESSION['admin_full_name'] = $setup_name;
                    $_SESSION['admin_email'] = $pd['email'];
                    $_SESSION['admin_role'] = $new_role;
                    $_SESSION['admin_id_number'] = $pd['id_number'] ?? null;
                    $_SESSION['account_status'] = 'active';
                    $_SESSION['must_change_password'] = 0;
                    $_SESSION['last_activity'] = time();
                    log_login($pdo, 'admin_users', $new_admin_id, $pd['username'], $setup_name, $new_role, 'login', 'success', $pd['id_number'] ?? null);
                    log_audit($pdo, 'register', 'admin_users', $new_admin_id, $setup_name, 'Staff account setup complete; activated as the only active account for role ' . $new_role);
                    redirect($new_role === 'super_admin' ? '../superadmin/dashboard.php' : 'dashboard.php');
                }
                $_SESSION['must_change_password'] = 0;
                log_audit($pdo, 'password_change', 'admin_users', $_SESSION['admin_id'], $_SESSION['admin_full_name'] ?? '', 'Password changed' . ($setup_required ? ' (forced setup)' : ''));
                $_SESSION['show_edit_profile_notice'] = true;
                $success = 'Password changed successfully. Redirecting to your dashboard...';
                $redirect_after = ($_SESSION['admin_role'] ?? '') === 'super_admin' ? '../superadmin/dashboard.php' : 'dashboard.php';
            } catch (Throwable $e) {
                if ($pdo->inTransaction()) { $pdo->rollBack(); }
                error_log('[change_password] ' . $e->getMessage());
                $error = $new_account_setup ? 'Failed to complete your account setup. Please try again.' : 'Failed to update your password. Please try again.';
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
            <h2 class="auth-title"><?php echo $new_account_setup ? 'Account Setup' : 'Change Password'; ?></h2>
            <p class="auth-subtitle"><?php echo $new_account_setup ? 'Set up your name, a secure password, and security questions before continuing.' : ($setup_required ? 'Complete your new account setup by changing your password and setting your security questions.' : 'Update your password and, optionally, your security questions.'); ?></p>

            <?php if ($new_account_setup): ?>
            <div class="alert alert-warning" style="margin-top:1rem;font-size:0.875rem;">
                <i class="fas fa-info-circle"></i>
                <span style="flex:1;min-width:0;">Complete your name, choose a secure password, and set all 3 security questions. When setup is complete, you will become the active <?php echo htmlspecialchars(ucfirst(str_replace('_', ' ', $_SESSION['pending_admin_data']['role'] ?? 'admin'))); ?> and continue to your dashboard.</span>
            </div>
            <?php elseif ($setup_required): ?>
            <div class="alert alert-warning" style="margin-top:1rem;font-size:0.875rem;">
                <i class="fas fa-exclamation-triangle"></i>
                <span style="flex:1;min-width:0;"><strong>Notice:</strong> Your account is new or your password was set by a Super Administrator. For security, you are required to <strong>change your password</strong> and <strong>set your security questions</strong> before you can access the admin panel.</span>
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
                <?php if ($new_account_setup): ?>
                <div class="form-group">
                    <label for="first_name"><i class="fas fa-user"></i> First Name *</label>
                    <input type="text" id="first_name" name="first_name" class="form-control" required maxlength="30" value="<?php echo htmlspecialchars($_POST['first_name'] ?? ''); ?>" placeholder="e.g. Juan" aria-describedby="firstNameStatus">
                    <small id="firstNameStatus" class="form-text" aria-live="polite">Capitalize each name word; use letters and single spaces only.</small>
                </div>
                <div class="form-group">
                    <label for="middle_name"><i class="fas fa-user"></i> Middle Initial (optional)</label>
                    <input type="text" id="middle_name" name="middle_name" class="form-control" maxlength="1" value="<?php echo htmlspecialchars($_POST['middle_name'] ?? ''); ?>" placeholder="e.g. S" aria-describedby="middleNameStatus">
                    <small id="middleNameStatus" class="form-text" aria-live="polite">Optional; enter one capital letter only.</small>
                </div>
                <div class="form-group">
                    <label for="last_name"><i class="fas fa-user"></i> Last Name *</label>
                    <input type="text" id="last_name" name="last_name" class="form-control" required maxlength="30" value="<?php echo htmlspecialchars($_POST['last_name'] ?? ''); ?>" placeholder="e.g. Dela Cruz" aria-describedby="lastNameStatus">
                    <small id="lastNameStatus" class="form-text" aria-live="polite">Capitalize each name word; use letters and single spaces only.</small>
                </div>
                <?php endif; ?>
                <div class="form-group">
                    <label for="new_password"><i class="fas fa-lock"></i> New Password</label>
                    <div class="password-wrapper">
                        <input type="password" id="new_password" name="new_password" class="form-control" placeholder="8-30 characters" required minlength="8" maxlength="30" autocomplete="new-password">
                        <button type="button" class="pw-toggle" onclick="togglePass('new_password',this)" tabindex="-1"><i class="fas fa-eye"></i></button>
                    </div>
                    <small id="passwordStrength" style="font-size:0.75rem;"></small>
                    <small class="form-text">Use 8-30 characters and combine letters with numbers or symbols. Avoid spaces.</small>
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
                                <div class="password-wrapper" style="margin-top:0.4rem;">
                                    <input type="password" id="sa<?php echo $i + 1; ?>" name="sa<?php echo $i + 1; ?>" class="form-control" placeholder="<?php echo $setup_required ? 'Your answer' : ($has_security ? 'Answer (blank keeps current)' : 'Your answer'); ?>" autocomplete="off" <?php echo $setup_required ? 'required' : ''; ?>>
                                    <button type="button" class="pw-toggle" onclick="togglePass('sa<?php echo $i + 1; ?>',this)" tabindex="-1" title="Show/hide answer"><i class="fas fa-eye"></i></button>
                                </div>
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
                <a href="../client/logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a>
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
    <?php if ($new_account_setup): ?>
    function validateSetupName(input, statusId, label, optional) {
        var value = input.value.trim();
        var message = '';
        if (!value && !optional) message = label + ' is required.';
        else if (value && (value.length < 2 || value.length > 30 || !/^[A-Z][a-z]+(?: [A-Z][a-z]+)*$/.test(value))) {
            message = 'Use capitalized name words only (for example, Juan Dela Cruz); no numbers or symbols.';
        }
        var status = document.getElementById(statusId);
        status.textContent = message || (value ? 'Looks good.' : (optional ? 'Optional; enter one capital letter only.' : 'Capitalize each name word; use letters and single spaces only.'));
        status.style.color = message ? 'var(--danger)' : (value ? 'var(--success)' : 'var(--muted)');
        input.setAttribute('aria-invalid', message ? 'true' : 'false');
        return !message;
    }
    function validateMiddleInitial(input) {
        var value = input.value.trim();
        var message = value && !/^[A-Z]$/.test(value) ? 'Enter one capital letter only (A-Z).' : '';
        var status = document.getElementById('middleNameStatus');
        status.textContent = message || (value ? 'Looks good.' : 'Optional; enter one capital letter only.');
        status.style.color = message ? 'var(--danger)' : (value ? 'var(--success)' : 'var(--muted)');
        input.setAttribute('aria-invalid', message ? 'true' : 'false');
        return !message;
    }
    ['first_name', 'last_name'].forEach(function (name) {
        var input = document.getElementById(name);
        var label = name === 'first_name' ? 'First name' : 'Last name';
        var statusId = name === 'first_name' ? 'firstNameStatus' : 'lastNameStatus';
        input.addEventListener('input', function () { validateSetupName(input, statusId, label, false); });
        input.addEventListener('blur', function () { validateSetupName(input, statusId, label, false); });
        validateSetupName(input, statusId, label, false);
    });
    var middleInput = document.getElementById('middle_name');
    middleInput.addEventListener('input', function () { validateMiddleInitial(middleInput); });
    middleInput.addEventListener('blur', function () { validateMiddleInitial(middleInput); });
    validateMiddleInitial(middleInput);
    document.getElementById('cpForm').addEventListener('submit', function (event) {
        var valid = validateSetupName(document.getElementById('first_name'), 'firstNameStatus', 'First name', false);
        valid = validateSetupName(document.getElementById('last_name'), 'lastNameStatus', 'Last name', false) && valid;
        valid = validateMiddleInitial(middleInput) && valid;
        if (!valid) event.preventDefault();
    });
    <?php endif; ?>
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
                var options = selects[i].options;
                for (var j = 0; j < options.length; j++) {
                    var questionId = options[j].value;
                    options[j].disabled = questionId !== '0' && selectedQuestions[questionId] === true && questionId !== selects[i].value;
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
