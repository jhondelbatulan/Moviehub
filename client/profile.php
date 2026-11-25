<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/authorization.php';
require_once '../includes/csrf.php';

require_login();
require_role('user');
require_status_active();

$upload_dir = '../uploads/profile_pictures/';
if (!file_exists($upload_dir)) { mkdir($upload_dir, 0777, true); }

$error = '';
$success = '';

$user = ['username'=>'','email'=>'','first_name'=>'','middle_initial'=>'','last_name'=>'','sex'=>'','birthdate'=>'','age'=>'','contact_number'=>'','address_street'=>'','profile_picture'=>''];

try {
    $stmt = $pdo->prepare("SELECT id, username, email, first_name, middle_initial, last_name, sex, birthdate, contact_number, address_street, IFNULL(profile_picture,'') as profile_picture FROM users WHERE id = ? LIMIT 1");
    $stmt->execute([$_SESSION['user_id']]);
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($result) { $user = array_merge($user, $result); $user['age'] = compute_age($user['birthdate']); }
    else { session_destroy(); header('Location: login.php'); exit(); }
} catch (PDOException $e) { error_log('Profile Error: '.$e->getMessage()); $error = 'Unable to retrieve user information.'; }

$display_full_name = trim(($user['first_name'] ?? '') . ' ' . ($user['middle_initial'] ?? '') . ' ' . ($user['last_name'] ?? ''));
$secret_questions = [];
$existing_security = [];
try {
    $secret_questions = $pdo->query("SELECT id, question_text FROM secret_questions WHERE is_active = 1 AND id IN (1, 2, 3) ORDER BY sort_order, id")->fetchAll(PDO::FETCH_ASSOC);
    $stmt = $pdo->prepare("SELECT question_id FROM security_answers WHERE user_table = 'users' AND user_id = ? ORDER BY id");
    $stmt->execute([$_SESSION['user_id']]);
    $existing_security = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log('[profile] Failed to load security questions: ' . $e->getMessage());
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token. Please try again.';
    } else {
        $email = trim($_POST['email'] ?? '');
        $first_name = trim($_POST['first_name'] ?? '');
        $middle_initial = strtoupper(trim($_POST['middle_initial'] ?? ''));
        $last_name = trim($_POST['last_name'] ?? '');
        $sex = $_POST['sex'] ?? '';
        $birthdate = trim($_POST['birthdate'] ?? '');
        $contact_number = trim($_POST['contact_number'] ?? '');
        $address_street = trim($_POST['address'] ?? '');
        $new_password = $_POST['new_password'] ?? '';
        $current_password = $_POST['current_password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';
        $sq_ids = [(int)($_POST['sq1_id'] ?? 0), (int)($_POST['sq2_id'] ?? 0), (int)($_POST['sq3_id'] ?? 0)];
        $sq_answers = [trim($_POST['sq1_answer'] ?? ''), trim($_POST['sq2_answer'] ?? ''), trim($_POST['sq3_answer'] ?? '')];
        $security_questions_changed = count(array_filter($sq_answers, function ($answer) { return $answer !== ''; })) > 0;
        $birthdate_valid = ($birthdate !== '' && DateTime::createFromFormat('Y-m-d', $birthdate) !== false && $birthdate <= date('Y-m-d'));

        $errors = [];
        if (($e = validate_name_field($first_name)) !== '') $errors[] = $e;
        if (($e = validate_name_field($last_name)) !== '') $errors[] = $e;
        if (($e = validate_middle_initial($middle_initial)) !== '') $errors[] = $e;
        if (!in_array($sex, ['Male', 'Female', 'Prefer not to say'], true)) $errors[] = 'Please select your gender.';
        if (!$birthdate_valid) $errors[] = 'Please enter a valid birth date (not in the future).';
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = 'Please enter a valid email address.';
        if (($e = validate_ph_contact($contact_number)) !== '') $errors[] = $e;
        if (($e = validate_address_field($address_street, 'Address')) !== '') $errors[] = $e;
        if ($security_questions_changed && in_array('', $sq_answers, true)) $errors[] = 'Fill in all three answers to update your security questions.';
        elseif ($security_questions_changed && !security_question_ids_are_valid($pdo, $sq_ids)) $errors[] = 'Choose three different active security questions.';
        if ($new_password !== '') {
            if ($current_password === '' || !check_user_password($pdo, 'users', $_SESSION['user_id'], $current_password)) $errors[] = 'Enter your current password to change it.';
            elseif (strlen($new_password) < 8 || strlen($new_password) > 30) $errors[] = 'New password must be 8-30 characters.';
            elseif ($new_password !== $confirm_password) $errors[] = 'Passwords do not match.';
        }

        if ($errors) {
            $error = implode(' ', array_slice($errors, 0, 3));
        } else {
            try {
                $pdo->beginTransaction();
                $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ? AND id != ?");
                $stmt->execute([$email, $_SESSION['user_id']]);
                if ($stmt->fetch()) throw new Exception('Email already taken.');

                $pic = $user['profile_picture'];
                if (isset($_FILES['profile_picture']) && $_FILES['profile_picture']['error'] === UPLOAD_ERR_OK) {
                    $ext = strtolower(pathinfo($_FILES['profile_picture']['name'], PATHINFO_EXTENSION));
                    if (!in_array($ext, ['jpg','jpeg','png'])) throw new Exception('Only JPG/PNG allowed.');
                    if ($_FILES['profile_picture']['size'] > 5*1024*1024) throw new Exception('Max 5MB.');
                    $new_filename = uniqid('profile_').'.'.$ext;
                    if (!move_uploaded_file($_FILES['profile_picture']['tmp_name'], $upload_dir.$new_filename)) throw new Exception('Upload failed.');
                    if (!empty($user['profile_picture']) && file_exists($upload_dir.$user['profile_picture'])) unlink($upload_dir.$user['profile_picture']);
                    $pic = $new_filename;
                }

                $middle_sql = $middle_initial !== '' ? $middle_initial : null;
                $sql = "UPDATE users SET email=:email, first_name=:fn, middle_initial=:mi, last_name=:ln, sex=:sex, birthdate=:bd, contact_number=:cn, address_street=:addr, profile_picture=:pic";
                $params = [':email'=>$email, ':fn'=>$first_name, ':mi'=>$middle_sql, ':ln'=>$last_name, ':sex'=>$sex, ':bd'=>$birthdate, ':cn'=>$contact_number, ':addr'=>$address_street, ':pic'=>$pic];
                if (!empty($new_password)) {
                    $sql .= ", password=:pwd";
                    $params[':pwd'] = password_hash($new_password, PASSWORD_DEFAULT);
                }
                $sql .= " WHERE id=:id";
                $params[':id'] = $_SESSION['user_id'];
                $stmt = $pdo->prepare($sql);
                $stmt->execute($params);
                if ($security_questions_changed) {
                    $pdo->prepare("DELETE FROM security_answers WHERE user_table = 'users' AND user_id = ?")->execute([$_SESSION['user_id']]);
                    $ins = $pdo->prepare("INSERT INTO security_answers (user_table, user_id, question_id, answer_hash) VALUES ('users', ?, ?, ?)");
                    for ($i = 0; $i < 3; $i++) {
                        $ins->execute([$_SESSION['user_id'], $sq_ids[$i], password_hash(strtolower($sq_answers[$i]), PASSWORD_DEFAULT)]);
                    }
                }
                $pdo->commit();
                log_audit($pdo, 'profile_update', 'users', $_SESSION['user_id'], $_SESSION['username'] ?? '', 'Own profile updated');
                $_SESSION['full_name'] = trim($first_name . ' ' . $middle_sql . ' ' . $last_name);
                $_SESSION['email'] = $email;
                $display_full_name = $_SESSION['full_name'];
                $success = 'Profile updated successfully!';
                $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
                $stmt->execute([$_SESSION['user_id']]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
                $user['age'] = compute_age($user['birthdate'] ?? '');
            } catch (Exception $e) {
                if ($pdo->inTransaction()) $pdo->rollBack();
                $error = $e->getMessage();
            }
        }
    }
}
generate_csrf_token();
$sexes = ['Male', 'Female', 'Prefer not to say'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profile - MovieHub</title>
    <link rel="stylesheet" href="../assets/css/style.css?v=2.3.0">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body>
    <?php require_once '../includes/navbar.php'; ?>
    <main class="mh-main">
        <div class="mh-page-head">
            <div>
                <h1 class="page-title">My Profile</h1>
                <p class="page-subtitle">Manage your personal information and account credentials</p>
            </div>
            <div class="header-actions"><a href="dashboard.php" class="btn btn-sm btn-outline"><i class="fas fa-arrow-left"></i> Back to Dashboard</a></div>
        </div>

            <div class="content-body">
                <?php if ($error): ?><div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div><?php endif; ?>
                <?php if ($success): ?><div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($success); ?></div><?php endif; ?>

                <div class="profile-header">
                    <div class="profile-avatar">
                        <?php if (!empty($user['profile_picture'])): ?>
                            <img src="../uploads/profile_pictures/<?php echo htmlspecialchars($user['profile_picture']); ?>" alt="Profile" class="avatar avatar-xl">
                        <?php else: ?>
                            <div class="avatar avatar-xl"><?php echo strtoupper(substr($display_full_name, 0, 1)); ?></div>
                        <?php endif; ?>
                    </div>
                    <div class="profile-info">
                        <h2><?php echo htmlspecialchars($display_full_name ?: $user['username']); ?></h2>
                        <p><i class="fas fa-user"></i> <?php echo htmlspecialchars($user['username']); ?></p>
                        <p><i class="fas fa-envelope"></i> <?php echo htmlspecialchars($user['email']); ?></p>
                    </div>
                </div>

                <form method="POST" action="" enctype="multipart/form-data" id="profileForm" novalidate>
                    <?php csrf_token_input(); ?>
                    <div class="card">
                        <div class="card-header"><h3 class="card-title"><i class="fas fa-address-card"></i> Personal Information</h3></div>
                        <div class="card-body">
                            <div class="form-row">
                                <div class="form-group">
                                    <label>Username</label>
                                    <input type="text" class="form-control" value="<?php echo htmlspecialchars($user['username']); ?>" readonly style="background:var(--background);">
                                    <small class="form-text">Username cannot be changed</small>
                                </div>
                                <div class="form-group">
                                    <label>Middle Initial</label>
                                    <input type="text" name="middle_initial" class="form-control" maxlength="1" placeholder="e.g., M" value="<?php echo htmlspecialchars($user['middle_initial'] ?? ''); ?>" oninput="this.value=this.value.toUpperCase()">
                                    <small class="form-text">One capital letter only</small>
                                </div>
                            </div>
                            <div class="form-row">
                                <div class="form-group">
                                    <label>First Name *</label>
                                    <input type="text" name="first_name" class="form-control" required maxlength="30" value="<?php echo htmlspecialchars($user['first_name'] ?? ''); ?>">
                                    <small class="form-text" id="fnStatus"></small>
                                </div>
                                <div class="form-group">
                                    <label>Last Name *</label>
                                    <input type="text" name="last_name" class="form-control" required maxlength="30" value="<?php echo htmlspecialchars($user['last_name'] ?? ''); ?>">
                                    <small class="form-text" id="lnStatus"></small>
                                </div>
                            </div>
                            <div class="form-row">
                                <div class="form-group">
                                    <label>Gender *</label>
                                    <select name="sex" class="form-control" required>
                                        <option value="">-- Select --</option>
                                        <?php foreach ($sexes as $s): ?>
                                            <option value="<?php echo $s; ?>" <?php echo ($user['sex'] ?? '') === $s ? 'selected' : ''; ?>><?php echo $s; ?></option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label>Birth Date *</label>
                                    <input type="date" name="birthdate" class="form-control" required max="<?php echo date('Y-m-d'); ?>" value="<?php echo htmlspecialchars($user['birthdate'] ?? ''); ?>">
                                </div>
                            </div>
                            <div class="form-row">
                                <div class="form-group">
                                    <label>Age</label>
                                    <input type="text" id="ageDisplay" class="form-control" readonly value="<?php echo $user['age'] !== '' ? $user['age'] . ' years' : ''; ?>" placeholder="Auto-computed">
                                </div>
                                <div class="form-group">
                                    <label>Contact Number *</label>
                                    <input type="text" name="contact_number" class="form-control" required placeholder="e.g., 0917-123-4567" value="<?php echo htmlspecialchars($user['contact_number'] ?? ''); ?>">
                                    <small class="form-text" id="cnStatus"></small>
                                </div>
                            </div>
                            <div class="form-group">
                                <label>Address</label>
                                <textarea name="address" class="form-control" rows="2" placeholder="Street, Barangay, City, Province, Zip"><?php echo htmlspecialchars($user['address_street'] ?? ''); ?></textarea>
                            </div>
                            <div class="form-group">
                                <label>Profile Picture</label>
                                <div class="profile-picture-container">
                                    <?php if (!empty($user['profile_picture'])): ?>
                                        <img src="../uploads/profile_pictures/<?php echo htmlspecialchars($user['profile_picture']); ?>" alt="Profile" class="current-profile-pic">
                                    <?php endif; ?>
                                </div>
                                <input type="file" name="profile_picture" class="form-control" accept="image/jpeg,image/png">
                                <small class="form-text">Max 5MB. JPG, PNG only.</small>
                            </div>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header"><h3 class="card-title"><i class="fas fa-key"></i> Account Credentials</h3></div>
                        <div class="card-body">
                            <div class="form-row">
                                <div class="form-group">
                                    <label>Email *</label>
                                    <input type="email" name="email" class="form-control" required value="<?php echo htmlspecialchars($user['email']); ?>">
                                    <small class="form-text" id="emStatus"></small>
                                </div>
                                <div class="form-group">
                                    <label>Current Password</label>
                                    <input type="password" name="current_password" class="form-control" autocomplete="current-password" placeholder="Required to change password">
                                </div>
                                <div class="form-group">
                                    <label>New Password</label>
                                    <input type="password" id="new_password" name="new_password" class="form-control" minlength="8" maxlength="30" placeholder="8-30 characters (leave blank to keep current)">
                                </div>
                            </div>
                            <div class="form-row">
                                <div class="form-group">
                                    <label>Confirm New Password</label>
                                    <input type="password" id="confirm_password" name="confirm_password" class="form-control" minlength="8" maxlength="30" placeholder="Re-enter new password">
                                </div>
                                <div class="form-group"></div>
                            </div>
                            <small style="font-size:0.75rem;color:var(--muted);">Changing your password here signs you in with the new password next time.</small>
                        </div>
                    </div>

                    <div class="card" style="margin-top:1rem;">
                        <div class="card-header"><h3 class="card-title"><i class="fas fa-shield-alt"></i> Security Questions</h3></div>
                        <div class="card-body">
                            <p class="form-text">Choose three different questions. Fill all three answers to replace your current recovery questions. Leave answers blank to keep them unchanged.</p>
                            <?php $profile_question_ids = ($error !== '' && $_SERVER['REQUEST_METHOD'] === 'POST') ? array_map('intval', [$_POST['sq1_id'] ?? 0, $_POST['sq2_id'] ?? 0, $_POST['sq3_id'] ?? 0]) : array_map('intval', array_column($existing_security, 'question_id')); ?>
                            <?php for ($i = 0; $i < 3; $i++): ?>
                                <div class="form-group">
                                    <label for="profile_sq<?php echo $i + 1; ?>">Security Question <?php echo $i + 1; ?></label>
                                    <select id="profile_sq<?php echo $i + 1; ?>" name="sq<?php echo $i + 1; ?>_id" class="form-control profile-sq-select">
                                        <option value="0" <?php echo empty($profile_question_ids[$i]) ? 'selected' : ''; ?>>-- Select a question --</option>
                                        <?php foreach ($secret_questions as $question): ?>
                                            <option value="<?php echo (int)$question['id']; ?>" <?php echo isset($profile_question_ids[$i]) && $profile_question_ids[$i] === (int)$question['id'] ? 'selected' : ''; ?>><?php echo htmlspecialchars($question['question_text']); ?></option>
                                        <?php endforeach; ?>
                                    </select>
                                    <input type="password" name="sq<?php echo $i + 1; ?>_answer" class="form-control" style="margin-top:0.4rem;" placeholder="Answer <?php echo $i + 1; ?>" autocomplete="off">
                                </div>
                            <?php endfor; ?>
                        </div>
                    </div>

                    <button type="submit" class="btn btn-primary" style="width:100%;margin-bottom:2rem;"><i class="fas fa-save"></i> Save Changes</button>
                </form>
            </div>
        </div>
    </main>
    <script>
    function nameOk(v){
        v=v.trim();
        if(!v) return false;
        if(v.length<2||v.length>30) return false;
        if(!/^[A-Z][a-z]+(?: [A-Z][a-z]+)*$/.test(v)) return false;
        if(/^[A-Z]+$/.test(v)) return false;
        if(/[0-9]/.test(v)||/[^A-Za-z ]/.test(v)) return false;
        if(/(.)\1{2,}/.test(v)) return false;
        return true;
    }
    function setStatus(id,msg,ok){ var el=document.getElementById(id); if(el){ el.textContent=msg; el.style.color=ok?'var(--success)':'var(--danger)'; } }
    var fn=document.getElementsByName('first_name')[0], ln=document.getElementsByName('last_name')[0];
    fn.addEventListener('input',function(){ var v=this.value.trim(); nameOk(v)?setStatus('fnStatus','Valid',true):setStatus('fnStatus',v?'First letter capital, no all-caps/3-same, no numbers/special chars.':'', false); });
    ln.addEventListener('input',function(){ var v=this.value.trim(); nameOk(v)?setStatus('lnStatus','Valid',true):setStatus('lnStatus',v?'First letter capital, no all-caps/3-same, no numbers/special chars.':'', false); });
    document.getElementsByName('email')[0].addEventListener('input',function(){ var v=this.value.trim(); /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)?setStatus('emStatus','Valid',true):setStatus('emStatus',v?'Invalid email':'',false); });
    function phOk(v){ v=v.trim(); var n=v.replace(/[^0-9]/g,''); if(n.indexOf('63')===0)n=n.substring(2); if(n.indexOf('0')===0)n=n.substring(1); return /^9\d{9}$/.test(n); }
    document.getElementsByName('contact_number')[0].addEventListener('input',function(){ var v=this.value.trim(); phOk(v)?setStatus('cnStatus','Valid',true):setStatus('cnStatus',v?'Use PH format, e.g. 0917-123-4567':'',false); });
    document.getElementsByName('birthdate')[0].addEventListener('input',function(){
        var d=this.value, ageEl=document.getElementById('ageDisplay');
        if(d){ var b=new Date(d), n=new Date(); var age=n.getFullYear()-b.getFullYear(); var m=n.getMonth()-b.getMonth(); if(m<0||(m===0&&n.getDate()<b.getDate()))age--; ageEl.value=(age>=0&&age<200)?age+' years':''; } else ageEl.value='';
    });
    document.getElementById('confirm_password').addEventListener('input', function() {
        var np = document.getElementById('new_password').value;
        np && this.value !== np ? this.setCustomValidity('Passwords do not match') : this.setCustomValidity('');
    });
    (function(){
        var selects = document.getElementsByClassName('profile-sq-select');
        function refresh(){
            var selected = {};
            for(var i=0;i<selects.length;i++){if(selects[i].value!=='0')selected[selects[i].value]=true;}
            for(var i=0;i<selects.length;i++){
                for(var j=0;j<selects[i].options.length;j++){
                    var option=selects[i].options[j];
                    option.disabled=option.value!=='0'&&selected[option.value]===true&&option.value!==selects[i].value;
                }
            }
        }
        for(var i=0;i<selects.length;i++)selects[i].addEventListener('change',refresh);
        refresh();
    })();
    </script>
</body>
</html>
