<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';
require_once '../includes/otp.php';
require_once '../includes/csrf.php';

$auth = new Auth($pdo);

if (isset($_SESSION['user_id'])) { header('Location: dashboard.php'); exit(); }

$error = '';
$success = '';

$secret_questions = [];
try {
    $stmt = $pdo->query("SELECT id, question_text FROM secret_questions WHERE is_active = 1 AND id IN (1, 2, 3) ORDER BY sort_order, id");
    $secret_questions = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) { error_log('[register] Failed to load questions: '.$e->getMessage()); }

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token. Please try again.';
    } else {
        $id_number = trim($_POST['id_number'] ?? '');
        $first_name = trim($_POST['first_name'] ?? '');
        $middle_initial = strtoupper(trim($_POST['middle_initial'] ?? ''));
        $last_name = trim($_POST['last_name'] ?? '');
        $extension_name = trim($_POST['extension_name'] ?? '');
        $sex = trim($_POST['sex'] ?? '');
        $birthdate = trim($_POST['birthdate'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $contact_number = trim($_POST['contact_number'] ?? '');
        $street = trim($_POST['address_street'] ?? '');
        $barangay = trim($_POST['address_barangay'] ?? '');
        $city = trim($_POST['address_city'] ?? '');
        $province = trim($_POST['address_province'] ?? '');
        $country = trim($_POST['address_country'] ?? '');
        $zip_code = trim($_POST['zip_code'] ?? '');
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';
        $sq_ids = [$_POST['sq1_id'] ?? '', $_POST['sq2_id'] ?? '', $_POST['sq3_id'] ?? ''];
        $sq_answers = [trim($_POST['sa1'] ?? ''), trim($_POST['sa2'] ?? ''), trim($_POST['sa3'] ?? '')];

        $valid_name = '/^[A-Z][a-z]+(?: [A-Z][a-z]+)*$/';
        $no_three = '/^(?:(.)(?!.*?\1\1\1))/';
        $all_caps = '/^[A-Z]+$/';
        $has_upper_after = '/[A-Z]/';
        $usernamePattern = '/^[A-Za-z](?=[A-Za-z0-9._]*[._0-9])[A-Za-z0-9._]{5,29}$/';
        $idNumberPattern = '/^\d{4}-\d{4}$/';
        $valid_ext = '/^(?:Jr\.?|Sr\.?|II|III|IV|V|VI|VII|VIII|IX|X)$/i';
        $valid = true;

        if ($id_number === '') { $error = 'ID Number is required.'; $valid = false; }
        elseif (!preg_match($idNumberPattern, $id_number)) { $error = 'ID Number must be in format xxxx-xxxx.'; $valid = false; }
        elseif ($first_name === '' || strlen($first_name) < 2 || strlen($first_name) > 30) { $error = 'First name must be 2-30 characters.'; $valid = false; }
        elseif (!preg_match($valid_name, $first_name)) { $error = 'First name must start with a capital letter with the rest in lowercase (e.g. Juan).'; $valid = false; }
        elseif (preg_match($all_caps, $first_name)) { $error = 'First name cannot be all capital letters.'; $valid = false; }
        elseif (preg_match('/[0-9]/', $first_name) || preg_match('/[^A-Za-z\s]/', $first_name)) { $error = 'First name cannot contain numbers or special characters.'; $valid = false; }
        elseif (preg_match('/(.)\1{2,}/', $first_name)) { $error = 'First name cannot have three or more consecutive identical letters.'; $valid = false; }
        elseif ($middle_initial !== '' && !preg_match('/^[A-Z]$/', $middle_initial)) { $error = 'Middle initial must be a single uppercase letter.'; $valid = false; }
        elseif ($last_name === '' || strlen($last_name) < 2 || strlen($last_name) > 30) { $error = 'Last name must be 2-30 characters.'; $valid = false; }
        elseif (!preg_match($valid_name, $last_name)) { $error = 'Last name must start with a capital letter with the rest in lowercase (e.g. Dela Cruz).'; $valid = false; }
        elseif (preg_match($all_caps, $last_name)) { $error = 'Last name cannot be all capital letters.'; $valid = false; }
        elseif (preg_match('/[0-9]/', $last_name) || preg_match('/[^A-Za-z\s]/', $last_name)) { $error = 'Last name cannot contain numbers or special characters.'; $valid = false; }
        elseif (preg_match('/(.)\1{2,}/', $last_name)) { $error = 'Last name cannot have three or more consecutive identical letters.'; $valid = false; }
        elseif ($extension_name !== '' && !preg_match($valid_ext, $extension_name)) { $error = 'Extension must be Jr., Sr., or a Roman numeral (II, III, IV, etc.).'; $valid = false; }
        elseif (!in_array($sex, ['Male','Female','Prefer not to say'], true)) { $error = 'Please select sex.'; $valid = false; }
        elseif ($birthdate === '') { $error = 'Birthdate is required.'; $valid = false; }
        elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) { $error = 'Valid email required.'; $valid = false; }
        elseif ($contact_number === '') { $error = 'Contact number required.'; $valid = false; }
        elseif ($street === '' || $barangay === '' || $city === '' || $province === '' || $country === '') { $error = 'All address fields are required.'; $valid = false; }
        elseif ($zip_code === '' || !ctype_digit($zip_code) || strlen($zip_code) < 4) { $error = 'Valid ZIP code required (min 4 digits).'; $valid = false; }
        elseif ($username === '' || !preg_match($usernamePattern, $username)) { $error = 'Username must start with a letter, 6-30 characters, using only letters, numbers, dots (.) or underscores (_), and must contain at least one dot, underscore, or number (e.g. user.jhondel, ai_chou, jamesmillare123).'; $valid = false; }
        elseif ($password !== $confirm_password) { $error = 'Passwords do not match.'; $valid = false; }
        elseif (strlen($password) < 8 || strlen($password) > 30) { $error = 'Password must be 8-30 characters.'; $valid = false; }
        elseif (in_array('', $sq_ids, true) || in_array('', $sq_answers, true)) { $error = 'All 3 security questions and answers are required.'; $valid = false; }
        elseif (count(array_unique($sq_ids)) !== 3) { $error = 'Security questions must be different.'; $valid = false; }
        elseif (!security_question_ids_are_valid($pdo, $sq_ids)) { $error = 'Choose three different active security questions.'; $valid = false; }

        if ($valid) {
            $data = [
                'id_number' => $id_number,
                'first_name' => $first_name,
                'middle_initial' => $middle_initial,
                'last_name' => $last_name,
                'extension_name' => $extension_name,
                'sex' => $sex,
                'birthdate' => $birthdate,
                'email' => $email,
                'contact_number' => $contact_number,
                'address_street' => $street,
                'address_barangay' => $barangay,
                'address_city' => $city,
                'address_province' => $province,
                'address_country' => $country,
                'zip_code' => $zip_code,
                'username' => $username,
                'password' => $password,
                'security_questions' => [],
            ];
            for ($i = 0; $i < 3; $i++) {
                $data['security_questions'][] = [
                    'question_id' => (int)$sq_ids[$i],
                    'answer' => $sq_answers[$i],
                ];
            }

            // Surface duplicate errors before sending the OTP so the user
            // does not have to verify an email for an unusable registration.
            $dup = username_taken($pdo, $username);
            if ($dup) {
                $error = 'Username is already taken. Please choose another one.';
            } else {
                if (email_taken($pdo, $email)) {
                    $error = 'An account with this email address already exists.';
                } else {
                    // The account is NOT created yet. Hold the registration in
                    // the session and require email OTP verification first;
                    // Auth::register_user() (which also submits the approval
                    // request) runs only after the OTP is confirmed.
                    $otp_key = (int)sprintf('%u', crc32(strtolower($email)));
                    if (!can_resend_otp($pdo, 'users', $otp_key, 'verification')) {
                        $error = 'Too many OTP requests for this email. Please wait before trying again.';
                    } else {
                        $otp = create_otp($pdo, 'users', $otp_key, 'verification');
                        $_SESSION['pending_registration'] = $data;
                        $_SESSION['pending_registration_otp_key'] = $otp_key;
                        $_SESSION['pending_registration_email'] = $email;
                        $_SESSION['pending_reg_otp_sent_at'] = time();
                        send_otp_email($email, $otp, $first_name . ' ' . $last_name, 'verification');
                        header('Location: verify_registration_otp.php');
                        exit();
                    }
                }
            }
        }
    }
}
$old = ($error !== '' && $_SERVER['REQUEST_METHOD'] === 'POST') ? $_POST : [];
generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - MovieHub</title>
    <link rel="stylesheet" href="../assets/css/style.css?v=2.3.0">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        html,body{height:100%;margin:0;padding:0;}
        body{overflow:auto;font-family:'Inter','Segoe UI',system-ui,-apple-system,sans-serif;}
        .reg-bg{min-height:calc(100vh - 64px);background:rgba(0,0,0,0.4);display:flex;flex-direction:column;margin-top:-1px;}
        .reg-main{flex:1;display:flex;align-items:center;justify-content:center;padding:1rem 1.5rem;}
        .reg-card{background:rgba(18,24,38,0.92);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border-radius:var(--radius-xl);box-shadow:0 20px 60px rgba(0,0,0,0.5);width:100%;max-width:1100px;border:1px solid var(--border-dark);overflow:hidden;}
        .reg-card-header{text-align:center;padding:0.75rem 1.5rem 0.25rem;}
        .reg-card-header h2{font-size:1.125rem;margin:0;color:#fff;}
        .reg-card-header p{color:var(--text-light);font-size:0.75rem;margin:0.125rem 0 0;}
        .step-indicator{display:flex;justify-content:center;gap:0;padding:0.5rem 1.5rem 0;}
        .step{display:flex;align-items:center;gap:0.5rem;font-size:0.8125rem;font-weight:500;color:var(--muted);}
        .step.active{color:var(--primary);}
        .step.completed{color:var(--success);}
        .step-num{width:24px;height:24px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:0.6875rem;font-weight:600;background:var(--background);color:var(--muted);border:2px solid var(--border);}
        .step.active .step-num{background:var(--primary);color:white;border-color:var(--primary);}
        .step.completed .step-num{background:var(--success-bg);color:var(--success);border-color:var(--success);}
        .reg-body{padding:0.5rem 1.5rem 0.75rem;}
        .reg-page{display:none;}
        .reg-page.active{display:block;}
        .reg-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:0.3rem 0.6rem;}
        .reg-grid .full{grid-column:1/-1;}
        .reg-grid .span2{grid-column:span 2;}
        .reg-grid .span3{grid-column:span 3;}
        .reg-grid .form-group{margin-bottom:0.2rem;}
        .reg-grid .form-group label{font-size:0.6875rem;font-weight:500;margin-bottom:0.1rem;display:block;color:var(--text-light);}
        .reg-grid .form-group input,.reg-grid .form-group select{padding:0.25rem 0.4rem;font-size:0.75rem;height:28px;box-sizing:border-box;background:#1a2234;border:1px solid #2e3a52;color:#f1f5f9;-webkit-text-fill-color:#f1f5f9;caret-color:#f1f5f9;color-scheme:dark;}
        .reg-grid .form-group input::placeholder{color:#8fa0b8;opacity:1;}
        .reg-grid .form-group input:focus{outline:none;border-color:var(--primary);}
        .reg-grid .form-group input:-webkit-autofill,.reg-grid .form-group input:-webkit-autofill:hover,.reg-grid .form-group input:-webkit-autofill:focus{-webkit-box-shadow:0 0 0 1000px #1a2234 inset;-webkit-text-fill-color:#f1f5f9;caret-color:#f1f5f9;}
        .sq-item input{background:#1a2234;border:1px solid #2e3a52;color:#f1f5f9 !important;-webkit-text-fill-color:#f1f5f9;caret-color:#f1f5f9;color-scheme:dark;}
        .sq-item input::placeholder{color:#8fa0b8;opacity:1;}
        .sq-item input:-webkit-autofill{-webkit-box-shadow:0 0 0 1000px #1a2234 inset;-webkit-text-fill-color:#f1f5f9;}
        .reg-grid .form-group small{font-size:0.625rem;min-height:0.8em;display:block;line-height:1.2;color:var(--muted);}
        .reg-grid .form-group .id-note{color:var(--primary);font-size:0.625rem;margin-top:0.1rem;min-height:0;}
        .sq-grid{display:grid;grid-template-columns:1fr;gap:0.6rem 1rem;}
        .sq-item{background:var(--background);border-radius:var(--radius);padding:0.6rem 0.75rem;}
        .sq-item label{font-size:0.75rem;font-weight:600;display:block;margin-bottom:0.25rem;}
        .reg-footer{padding:0.375rem 1.5rem 0.75rem;display:flex;justify-content:space-between;gap:0.5rem;}
        .reg-footer .btn{flex:1;padding:0.4rem 0.75rem;font-size:0.8125rem;}
        .reg-links{text-align:center;padding:0.375rem 1.5rem 0.75rem;font-size:0.75rem;color:var(--text-light);}
        .reg-links a{color:var(--primary);}
        .pw-toggle{position:absolute;right:4px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;color:var(--text-light);padding:2px 4px;font-size:0.8rem;}
        .pw-toggle:hover{color:var(--primary);}
        @media(max-width:900px){.reg-grid{grid-template-columns:repeat(2,1fr);}.reg-grid .span3{grid-column:span 2;}}
        @media(max-width:500px){.reg-grid{grid-template-columns:1fr;}.reg-grid .span2,.reg-grid .span3{grid-column:1/-1;}.reg-card{margin:0.5rem;}}
    </style>
</head>
<body style="background: url('../assets/homepage.jpg') center/cover no-repeat fixed; background-color: #1a1a2e;">
    <?php require_once '../includes/header_public.php'; ?>
    <div class="reg-bg">

        <main class="reg-main">
            <div class="reg-card">
                <div class="reg-card-header">
                    <h2><i class="fas fa-user-plus" style="color:var(--primary);"></i> Create Account</h2>
                    <p>Fill in your details to get started</p>
                </div>
                <div class="step-indicator">
                    <div class="step active" id="step1ind"><div class="step-num">1</div> Personal Info</div>
                    <div style="width:40px;height:2px;background:var(--border);margin:0 0.5rem;align-self:center;"></div>
                    <div class="step" id="step2ind"><div class="step-num">2</div> Security</div>
                </div>

                <?php if ($error): ?><div class="alert alert-danger" style="margin:0.5rem 1rem;font-size:0.8125rem;"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div><?php endif; ?>
                <?php if ($success): ?><div class="alert alert-success" style="margin:0.5rem 1rem;font-size:0.8125rem;"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($success); ?></div><?php endif; ?>

                <form method="POST" action="" novalidate id="regForm">
                    <?php csrf_token_input(); ?>
                    <input type="hidden" name="sq1_id" id="sq1_id" value="<?php echo htmlspecialchars($old['sq1_id'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">
                    <input type="hidden" name="sq2_id" id="sq2_id" value="<?php echo htmlspecialchars($old['sq2_id'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">
                    <input type="hidden" name="sq3_id" id="sq3_id" value="<?php echo htmlspecialchars($old['sq3_id'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">

                    <div class="reg-page active" id="page1">
                        <div class="reg-body">
                            <div class="reg-grid">
                                <div class="form-group full"><label>ID Number</label><input type="text" id="id_number" name="id_number" required placeholder="xxxx-xxxx" maxlength="9" value="<?php echo htmlspecialchars($old['id_number'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" readonly aria-readonly="true"><small id="idNumberStatus"></small><small class="id-note"><i class="fas fa-info-circle"></i> Your ID number is generated automatically and cannot be changed. Remember it for login and password recovery.</small></div>
                                <div class="form-group"><label>First Name *</label><input type="text" id="first_name" name="first_name" required value="<?php echo htmlspecialchars($old['first_name'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"><small id="firstNameStatus"></small></div>
                                <div class="form-group"><label>Middle Initial</label><input type="text" id="middle_initial" name="middle_initial" maxlength="1" value="<?php echo htmlspecialchars($old['middle_initial'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"></div>
                                <div class="form-group"><label>Last Name *</label><input type="text" id="last_name" name="last_name" required value="<?php echo htmlspecialchars($old['last_name'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"><small id="lastNameStatus"></small></div>
                                <div class="form-group"><label>Extension</label><input type="text" id="extension_name" name="extension_name" placeholder="Jr, Sr, III" value="<?php echo htmlspecialchars($old['extension_name'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"><small id="extensionStatus"></small></div>
                                <div class="form-group"><label>Sex *</label><select id="sex" name="sex" required><option value="" disabled <?php echo empty($old['sex']) ? 'selected' : ''; ?>>Select</option><option value="Male" <?php echo ($old['sex'] ?? '') === 'Male' ? 'selected' : ''; ?>>Male</option><option value="Female" <?php echo ($old['sex'] ?? '') === 'Female' ? 'selected' : ''; ?>>Female</option><option value="Prefer not to say" <?php echo ($old['sex'] ?? '') === 'Prefer not to say' ? 'selected' : ''; ?>>Prefer not to say</option></select></div>
                                <div class="form-group"><label>Birthdate *</label><input type="date" id="birthdate" name="birthdate" required value="<?php echo htmlspecialchars($old['birthdate'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"></div>
                                <div class="form-group"><label>Age</label><input type="number" id="age" readonly></div>
                                <div class="form-group"><label>Contact Number *</label><input type="tel" id="contact_number" name="contact_number" required value="<?php echo htmlspecialchars($old['contact_number'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"><small id="contactStatus"></small></div>
                                <div class="form-group full" style="margin-top:0.15rem;"><label style="font-weight:600;color:var(--secondary);font-size:0.75rem;"><i class="fas fa-map-marker-alt"></i> Address</label></div>
                                <div class="form-group span3"><label>Purok/Street *</label><input type="text" id="address_street" name="address_street" required value="<?php echo htmlspecialchars($old['address_street'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"></div>
                                <div class="form-group"><label>Barangay *</label><input type="text" id="address_barangay" name="address_barangay" required value="<?php echo htmlspecialchars($old['address_barangay'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"></div>
                                <div class="form-group"><label>Municipal/City *</label><input type="text" id="address_city" name="address_city" required value="<?php echo htmlspecialchars($old['address_city'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"></div>
                                <div class="form-group"><label>Province *</label><input type="text" id="address_province" name="address_province" required value="<?php echo htmlspecialchars($old['address_province'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"></div>
                                <div class="form-group"><label>Country *</label><input type="text" id="address_country" name="address_country" required value="<?php echo htmlspecialchars($old['address_country'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"></div>
                                <div class="form-group"><label>ZIP Code *</label><input type="text" id="zip_code" name="zip_code" inputmode="numeric" maxlength="6" required value="<?php echo htmlspecialchars($old['zip_code'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"><small id="zipStatus"></small></div>
                                <div class="form-group"><label>Email *</label><input type="email" id="email" name="email" required value="<?php echo htmlspecialchars($old['email'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"><small id="emailStatus"></small></div>
                                <div class="form-group"><label>Username *</label><input type="text" id="username" name="username" required autocomplete="off" value="<?php echo htmlspecialchars($old['username'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"><small id="usernameStatus"></small></div>
                                <div class="form-group"><label>Password *</label><div style="position:relative;"><input type="password" id="password" name="password" required autocomplete="new-password" style="padding-right:1.8rem;"><button type="button" onclick="togglePass('password',this)" class="pw-toggle" aria-label="Toggle password"><i class="fas fa-eye"></i></button></div><small id="passwordStrength"></small></div>
                                <div class="form-group"><label>Confirm Password *</label><div style="position:relative;"><input type="password" id="confirm_password" name="confirm_password" required autocomplete="new-password" style="padding-right:1.8rem;"><button type="button" onclick="togglePass('confirm_password',this)" class="pw-toggle" aria-label="Toggle password"><i class="fas fa-eye"></i></button></div><small id="confirmStatus"></small></div>
                            </div>
                        </div>
                        <div class="reg-footer">
                            <a href="../index.php" class="btn btn-outline"><i class="fas fa-arrow-left"></i> Back</a>
                            <button type="button" class="btn btn-primary" onclick="goToPage2()">Next <i class="fas fa-arrow-right"></i></button>
                        </div>
                    </div>

                    <div class="reg-page" id="page2">
                        <div class="reg-body">
                            <p style="font-size:0.75rem;color:var(--text-light);margin-bottom:0.5rem;">Choose 3 different security questions. These will be used to verify your identity when resetting your password.</p>
                            <div class="sq-grid">
                                <div class="sq-item">
                                    <label><i class="fas fa-shield-alt" style="color:var(--primary);"></i> Security Question 1 *</label>
                                    <select name="sq1_raw" id="sq1_raw" class="form-control" required style="height:28px;font-size:0.75rem;margin-bottom:0.25rem;" onchange="syncHiddenId(this,'sq1_id')">
                                        <option value="" disabled <?php echo empty($old['sq1_raw']) ? 'selected' : ''; ?>>Select a question</option>
                                        <?php foreach ($secret_questions as $q): ?><option value="<?php echo $q['id']; ?>" <?php echo (string)($old['sq1_raw'] ?? '') === (string)$q['id'] ? 'selected' : ''; ?>><?php echo htmlspecialchars($q['question_text']); ?></option><?php endforeach; ?>
                                    </select>
                                    <div style="position:relative;"><input type="password" name="sa1" id="sa1" class="form-control" placeholder="Your answer" required autocomplete="new-password" style="height:28px;font-size:0.75rem;padding-right:1.8rem;"><button type="button" onclick="togglePass('sa1',this)" class="pw-toggle" aria-label="Toggle answer"><i class="fas fa-eye"></i></button></div>
                                </div>
                                <div class="sq-item">
                                    <label><i class="fas fa-shield-alt" style="color:var(--primary);"></i> Security Question 2 *</label>
                                    <select name="sq2_raw" id="sq2_raw" class="form-control" required style="height:28px;font-size:0.75rem;margin-bottom:0.25rem;" onchange="syncHiddenId(this,'sq2_id')">
                                        <option value="" disabled <?php echo empty($old['sq2_raw']) ? 'selected' : ''; ?>>Select a question</option>
                                        <?php foreach ($secret_questions as $q): ?><option value="<?php echo $q['id']; ?>" <?php echo (string)($old['sq2_raw'] ?? '') === (string)$q['id'] ? 'selected' : ''; ?>><?php echo htmlspecialchars($q['question_text']); ?></option><?php endforeach; ?>
                                    </select>
                                    <div style="position:relative;"><input type="password" name="sa2" id="sa2" class="form-control" placeholder="Your answer" required autocomplete="new-password" style="height:28px;font-size:0.75rem;padding-right:1.8rem;"><button type="button" onclick="togglePass('sa2',this)" class="pw-toggle" aria-label="Toggle answer"><i class="fas fa-eye"></i></button></div>
                                </div>
                                <div class="sq-item">
                                    <label><i class="fas fa-shield-alt" style="color:var(--primary);"></i> Security Question 3 *</label>
                                    <select name="sq3_raw" id="sq3_raw" class="form-control" required style="height:28px;font-size:0.75rem;margin-bottom:0.25rem;" onchange="syncHiddenId(this,'sq3_id')">
                                        <option value="" disabled <?php echo empty($old['sq3_raw']) ? 'selected' : ''; ?>>Select a question</option>
                                        <?php foreach ($secret_questions as $q): ?><option value="<?php echo $q['id']; ?>" <?php echo (string)($old['sq3_raw'] ?? '') === (string)$q['id'] ? 'selected' : ''; ?>><?php echo htmlspecialchars($q['question_text']); ?></option><?php endforeach; ?>
                                    </select>
                                    <div style="position:relative;"><input type="password" name="sa3" id="sa3" class="form-control" placeholder="Your answer" required autocomplete="new-password" style="height:28px;font-size:0.75rem;padding-right:1.8rem;"><button type="button" onclick="togglePass('sa3',this)" class="pw-toggle" aria-label="Toggle answer"><i class="fas fa-eye"></i></button></div>
                                </div>
                            </div>
                        </div>
                        <div class="reg-footer">
                            <button type="button" class="btn btn-outline" onclick="goToPage1()"><i class="fas fa-arrow-left"></i> Back</button>
                            <button type="submit" class="btn btn-success"><i class="fas fa-user-plus"></i> Register</button>
                        </div>
                    </div>
                </form>

                <div class="reg-links">Already have an account? <a href="login.php">Login here</a></div>
            </div>
        </main>
        <footer style="flex-shrink:0;padding:0.5rem;text-align:center;color:rgba(255,255,255,0.7);font-size:0.75rem;">&copy; <?php echo date('Y'); ?> MovieHub. All rights reserved.</footer>
    </div>
    <div id="regSuccessModal" class="modal" style="display:none;"><div class="modal-content"><div class="modal-header"><h3 class="modal-title"><i class="fas fa-check-circle" style="color:var(--success);"></i> Registration Successful</h3></div><div class="modal-body"><p>Your account has been created successfully. It is pending admin approval.</p><div style="display:flex;gap:0.5rem;margin-top:1rem;"><a href="login.php" class="btn btn-primary" style="flex:1;">Back to Login</a></div></div></div></div>

    <script>
    (function(){ var m=document.getElementById('regSuccessModal'); if('<?php echo $success; ?>'.length>0&&m){m.style.display='flex';window.addEventListener('click',(e)=>{if(e.target===m)m.style.display='none';});}})();
    function togglePass(id,btn){var i=document.getElementById(id);var icon=btn.querySelector('i');if(i.type==='password'){i.type='text';icon.classList.replace('fa-eye','fa-eye-slash');}else{i.type='password';icon.classList.replace('fa-eye-slash','fa-eye');}}
    function syncHiddenId(sel, hiddenId){ document.getElementById(hiddenId).value = sel.value; }
    document.addEventListener('DOMContentLoaded',function(){
        var $=function(id){return document.getElementById(id);};

        function goToPage2(){
            var fn=$('first_name'),ln=$('last_name'),mi=$('middle_initial'),ex=$('extension_name');
            var ok=true;
            if (!$('email').checkValidity()) { $('email').reportValidity(); ok=false; }
            if(fn.value.trim()&&!validateNameInput(fn,$('firstNameStatus'),'First name'))ok=false;
            if(ln.value.trim()&&!validateNameInput(ln,$('lastNameStatus'),'Last name'))ok=false;
            if(mi.value.trim()&&!/^[A-Z]$/.test(mi.value.trim())){$('firstNameStatus').textContent='Middle initial must be a single uppercase letter';$('firstNameStatus').style.color='var(--danger)';ok=false;}
            if(ex.value.trim()&&!/^(?:Jr\.?|Sr\.?|II|III|IV|V|VI|VII|VIII|IX|X)$/i.test(ex.value.trim())){$('extensionStatus').textContent='Jr., Sr., II, III, IV, V–X only';$('extensionStatus').style.color='var(--danger)';ok=false;}
            if(!ok){return;}
            document.getElementById('page1').classList.remove('active');
            document.getElementById('page2').classList.add('active');
            document.getElementById('step1ind').classList.remove('active');
            document.getElementById('step1ind').classList.add('completed');
            document.getElementById('step2ind').classList.add('active');
            document.querySelector('.reg-card').scrollIntoView({behavior:'smooth',block:'start'});
        }
        function goToPage1(){
            document.getElementById('page2').classList.remove('active');
            document.getElementById('page1').classList.add('active');
            document.getElementById('step2ind').classList.remove('active');
            document.getElementById('step1ind').classList.remove('completed');
            document.getElementById('step1ind').classList.add('active');
        }

        window.goToPage2 = goToPage2;
        window.goToPage1 = goToPage1;

        function computeAge(d){var t=new Date(),b=new Date(d);var a=t.getFullYear()-b.getFullYear();if(t.getMonth()<b.getMonth()||(t.getMonth()===b.getMonth()&&t.getDate()<b.getDate()))a--;return a>=0?a:'';}
        $('birthdate').addEventListener('change',function(){$('age').value=computeAge(this.value);});
        (async()=>{try{var r=await fetch('get_next_id.php');var d=await r.json();if(d.ok&&d.id_number&&!$('id_number').value){$('id_number').value=d.id_number;var s=$('idNumberStatus');if(s){s.textContent='Auto-generated';s.style.color='var(--success)';}}}catch(e){}})();
        var idTimer;$('id_number').addEventListener('input',function(e){var v=e.target.value.replace(/[^\d-]/g,'');var d=v.replace(/-/g,'');if(d.length>4)v=d.substring(0,4)+'-'+d.substring(4,8);else v=d;e.target.value=v;var s=$('idNumberStatus');if(!v){s.textContent='';e.target.setCustomValidity('');}else if(v.length===9&&/^\d{4}-\d{4}$/.test(v)){s.textContent='Valid format';s.style.color='var(--success)';clearTimeout(idTimer);idTimer=setTimeout(async()=>{try{var r=await fetch('check_id.php?id_number='+encodeURIComponent(v));var d=await r.json();if(d.ok){s.textContent=d.exists?'ID already exists':'ID available';s.style.color=d.exists?'var(--danger)':'var(--success)';e.target.setCustomValidity(d.exists?'Exists':'');}}catch(e){}},450);}else{s.textContent='Format: xxxx-xxxx';s.style.color='var(--danger)';e.target.setCustomValidity('Invalid');}});
        var uPattern=/^[A-Za-z](?=[A-Za-z0-9._]*[._0-9])[A-Za-z0-9._]{5,29}$/;var uTimer;$('username').addEventListener('input',function(){clearTimeout(uTimer);var s=$('usernameStatus');var u=this.value.trim();if(!u){s.textContent='';return;}if(!uPattern.test(u)){s.textContent='Start with a letter; 6-30 chars; letters, numbers, . or _; must include . _ or a number';s.style.color='var(--danger)';return;}uTimer=setTimeout(async()=>{try{var r=await fetch('check_username.php?username='+encodeURIComponent(u));var d=await r.json();if(d.ok){s.textContent=d.available?'Username available':'Username taken';s.style.color=d.available?'var(--success)':'var(--danger)';}}catch(e){}},400);});
        var ePattern=/^[^\s@]+@[^\s@]+\.[^\s@]+$/;var eTimer,emailRequest=0;function checkEmail(){clearTimeout(eTimer);var em=$('email').value.trim(),s=$('emailStatus'),request=++emailRequest;$('email').setCustomValidity('');if(!em){s.textContent='';return;}if(!ePattern.test(em)){s.textContent='Invalid email';s.style.color='var(--danger)';$('email').setCustomValidity('Enter a valid email address.');return;}s.textContent='Checking email…';s.style.color='var(--muted)';$('email').setCustomValidity('Checking email availability.');eTimer=setTimeout(async()=>{try{var r=await fetch('check_email.php?email='+encodeURIComponent(em));var d=await r.json();if(request!==emailRequest||em!==$('email').value.trim())return;if(d.ok){s.textContent=d.available?'Email available':'Email already used';s.style.color=d.available?'var(--success)':'var(--danger)';$('email').setCustomValidity(d.available?'':'Email already used. Enter a different email address.');}}catch(e){if(request===emailRequest)$('email').setCustomValidity('');}},400);} $('email').addEventListener('input',checkEmail);if($('email').value.trim())checkEmail();
        $('password').addEventListener('input',function(){var p=this.value;var s=$('passwordStrength');var score=0;if(p.length>=8)score++;if(/[a-z]/.test(p)&&/[A-Z]/.test(p))score++;if(/\d/.test(p))score++;if(/[^A-Za-z0-9]/.test(p))score++;var labels=['Weak','Medium','Strong','Very Strong'];var colors=['var(--danger)','var(--warning)','var(--success)','var(--success)'];s.textContent=labels[Math.max(0,score-1)]||'';s.style.color=colors[Math.max(0,score-1)]||'';});
        function validateNameInput(el,statusEl,label){
            var v=el.value.trim(),s=statusEl;
            if(!v){s.textContent='';el.setCustomValidity('');return true;}
            var pat=/^[A-Z][a-z]+(?: [A-Z][a-z]+)*$/;
            if(!pat.test(v)){s.textContent=label+' must start with a capital letter, rest lowercase';s.style.color='var(--danger)';el.setCustomValidity('Invalid');return false;}
            if(/^[A-Z]+$/.test(v)){s.textContent=label+' cannot be all caps';s.style.color='var(--danger)';el.setCustomValidity('Invalid');return false;}
            if(/[0-9]/.test(v)||/[^A-Za-z\s]/.test(v)){s.textContent=label+' cannot contain numbers or special characters';s.style.color='var(--danger)';el.setCustomValidity('Invalid');return false;}
            if(/(.)\1{2,}/.test(v)){s.textContent=label+' cannot have three consecutive identical letters';s.style.color='var(--danger)';el.setCustomValidity('Invalid');return false;}
            s.textContent='Valid '+label.toLowerCase();s.style.color='var(--success)';el.setCustomValidity('');return true;
        }
        var fTimer;$('first_name').addEventListener('input',function(){var s=$('firstNameStatus');var v=this.value.trim();if(!v){s.textContent='';this.setCustomValidity('');return;}clearTimeout(fTimer);var self=this;fTimer=setTimeout(function(){validateNameInput(self,s,'First name');},300);});
        var lTimer;$('last_name').addEventListener('input',function(){var s=$('lastNameStatus');var v=this.value.trim();if(!v){s.textContent='';this.setCustomValidity('');return;}clearTimeout(lTimer);var self=this;lTimer=setTimeout(function(){validateNameInput(self,s,'Last name');},300);});
        $('middle_initial').addEventListener('input',function(){var v=this.value.trim();this.value=v?v.charAt(0).toUpperCase():'';});
        var extPat=/^(?:Jr\.?|Sr\.?|II|III|IV|V|VI|VII|VIII|IX|X)$/i;
        var eTimer2;$('extension_name').addEventListener('input',function(){var s=$('extensionStatus');var v=this.value.trim();clearTimeout(eTimer2);if(!v){s.textContent='';this.setCustomValidity('');return;}eTimer2=setTimeout(function(){if(extPat.test(v)){s.textContent='Valid extension';s.style.color='var(--success)';$('extension_name').setCustomValidity('');}else{s.textContent='Jr., Sr., II, III, IV, V–X only';s.style.color='var(--danger)';$('extension_name').setCustomValidity('Invalid');}},300);});
        function checkConfirm(){var ok=$('password').value===$('confirm_password').value&&$('confirm_password').value.length>0;$('confirmStatus').textContent=ok?'Passwords match':($('confirm_password').value?'Passwords do not match':'');$('confirmStatus').style.color=ok?'var(--success)':'var(--danger)';}
        $('confirm_password').addEventListener('input',checkConfirm);$('password').addEventListener('input',checkConfirm);
    var questionSelects=['sq1_raw','sq2_raw','sq3_raw'];function refreshQuestionChoices(){var selected={};questionSelects.forEach(function(id){if($(id).value)selected[$(id).value]=true;});questionSelects.forEach(function(id){var select=$(id);Array.prototype.forEach.call(select.options,function(option){option.disabled=option.value!==''&&selected[option.value]===true&&option.value!==select.value;});});questionSelects.forEach(function(id){var select=$(id),hiddenId=id.replace('_raw','_id');$(hiddenId).value=select.value;});}questionSelects.forEach(function(id){$(id).addEventListener('change',refreshQuestionChoices);});refreshQuestionChoices();
    });
    </script>
</body>
</html>
