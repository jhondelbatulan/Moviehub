<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/authorization.php';
require_once '../includes/auth.php';
require_once '../includes/csrf.php';

require_login();
require_role('super_admin');
require_permission('admins.create');

$auth = new Auth($pdo);
$success = '';
$error = '';
$role = 'admin';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token.';
    } else {
        $first_name = trim($_POST['first_name'] ?? '');
        $last_name = trim($_POST['last_name'] ?? '');
        $username = trim($_POST['username'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';
        $role = $_POST['role'] ?? 'admin';
        $phone = trim($_POST['phone'] ?? '');
        $id_number = trim($_POST['id_number'] ?? '');

        $valid_name = '/^[A-Z][a-z]+(?: [A-Z][a-z]+)*$/';
        $all_caps = '/^[A-Z]+$/';
        $idNumberPattern = '/^\d{4}-\d{4}$/';

        if (empty($first_name) || empty($last_name) || empty($username) || empty($email) || empty($password)) {
            $error = 'All required fields must be filled.';
        } elseif ($id_number === '') {
            $error = 'ID Number is required.';
        } elseif (!preg_match($idNumberPattern, $id_number)) {
            $error = 'ID Number must be in format xxxx-xxxx (e.g. 1234-5678).';
        } elseif (strlen($first_name . ' ' . $last_name) > 100) {
            $error = 'Full name is too long.';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = 'Invalid email address.';
        } elseif ($password !== $confirm_password) {
            $error = 'Passwords do not match.';
        } elseif (strlen($password) < 8 || strlen($password) > 30) {
            $error = 'Password must be 8-30 characters.';
        } elseif (!in_array($role, ['admin', 'super_admin'])) {
            $error = 'Invalid role.';
        } elseif (strlen($first_name) < 2 || strlen($first_name) > 30) {
            $error = 'First name must be 2-30 characters.';
        } elseif (!preg_match($valid_name, $first_name)) {
            $error = 'First name must start with a capital letter with the rest in lowercase (e.g. Juan).';
        } elseif (preg_match($all_caps, $first_name)) {
            $error = 'First name cannot be all capital letters.';
        } elseif (preg_match('/[0-9]/', $first_name) || preg_match('/[^A-Za-z\s]/', $first_name)) {
            $error = 'First name cannot contain numbers or special characters.';
        } elseif (preg_match('/(.)\1{2,}/', $first_name)) {
            $error = 'First name cannot have three or more consecutive identical letters.';
        } elseif (strlen($last_name) < 2 || strlen($last_name) > 30) {
            $error = 'Last name must be 2-30 characters.';
        } elseif (!preg_match($valid_name, $last_name)) {
            $error = 'Last name must start with a capital letter with the rest in lowercase (e.g. Dela Cruz).';
        } elseif (preg_match($all_caps, $last_name)) {
            $error = 'Last name cannot be all capital letters.';
        } elseif (preg_match('/[0-9]/', $last_name) || preg_match('/[^A-Za-z\s]/', $last_name)) {
            $error = 'Last name cannot contain numbers or special characters.';
        } elseif (preg_match('/(.)\1{2,}/', $last_name)) {
            $error = 'Last name cannot have three or more consecutive identical letters.';
        } elseif (!preg_match('/^[A-Za-z][A-Za-z0-9_]{7,29}$/', $username)) {
            $error = 'Username must start with a letter and be 8-30 characters (letters, numbers, underscore).';
        } elseif ($phone !== '' && (!ctype_digit(preg_replace('/[^0-9]/', '', $phone)) || strlen(preg_replace('/[^0-9]/', '', $phone)) < 7 || strlen(preg_replace('/[^0-9]/', '', $phone)) > 15)) {
            $error = 'Phone number must contain 7-15 digits.';
        } else {
            $result = $auth->register_admin([
                'full_name' => $first_name . ' ' . $last_name,
                'username' => $username,
                'email' => $email,
                'password' => $password,
                'role' => $role,
                'phone' => $phone,
                'id_number' => $id_number,
            ], $_SESSION['admin_role']);

            if ($result['success']) {
                $success = $result['message'];
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
    <title>Create Account - MovieHub</title>
    <link rel="stylesheet" href="../assets/css/style.css?v=2.3.0">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body>
    <div class="page-wrapper">
        <aside class="sidebar" id="sidebar">
            <div class="sidebar-header"><a href="dashboard.php" class="sidebar-logo"><i class="fas fa-film"></i><span>MovieHub</span></a></div>
            <nav class="sidebar-nav">
                <div class="sidebar-section"><div class="sidebar-section-title">Overview</div>
                    <a href="dashboard.php" class="sidebar-link"><i class="fas fa-tachometer-alt"></i><span>Dashboard</span></a>
                </div>
                <div class="sidebar-section"><div class="sidebar-section-title">User Management</div>
                    <a href="account_management.php" class="sidebar-link"><i class="fas fa-users-cog"></i><span>Account Management</span></a>
                    <a href="create_account.php" class="sidebar-link active"><i class="fas fa-user-plus"></i><span>Create Account</span></a>
                    <a href="privilege_management.php" class="sidebar-link"><i class="fas fa-shield-alt"></i><span>Privileges</span></a>
                    <a href="../admin/registration_approval.php" class="sidebar-link"><i class="fas fa-user-check"></i><span>Registration Approvals</span></a>
                    <a href="deletion_requests.php" class="sidebar-link"><i class="fas fa-user-minus"></i><span>Deletion Requests</span></a>
                </div>
                <div class="sidebar-section"><div class="sidebar-section-title">Activity</div>
                    <a href="../admin/login_logs.php" class="sidebar-link"><i class="fas fa-history"></i><span>Login Logs</span></a>
                </div>
                <div class="sidebar-section"><div class="sidebar-section-title">Account</div>
                    <a href="../client/logout.php" class="sidebar-link"><i class="fas fa-sign-out-alt"></i><span>Logout</span></a>
                </div>
            </nav>
            <a href="edit_admin.php?id=<?php echo (int)$_SESSION['admin_id']; ?>" class="sidebar-user" style="display:flex;align-items:center;gap:0.75rem;padding:0.75rem 1rem;color:inherit;text-decoration:none;transition:background 0.15s;cursor:pointer;" title="Edit my profile">
                <div class="avatar avatar-sm" style="background:var(--primary);color:white;"><?php echo strtoupper(substr($_SESSION['admin_full_name'], 0, 1)); ?></div>
                <div class="sidebar-user-info">
                    <div class="sidebar-user-name"><?php echo htmlspecialchars($_SESSION['admin_full_name']); ?></div>
                    <div class="sidebar-user-role" style="color:var(--primary);font-weight:600;">Super Admin</div>
                </div>
            </a>
        </aside>

        <div class="main-content">
            <div class="top-header">
                <div class="flex items-center gap-3">
                    <button class="sidebar-toggle" onclick="document.getElementById('sidebar').classList.toggle('open');document.getElementById('sidebarOverlay').classList.toggle('active');"><i class="fas fa-bars"></i></button>
                    <div><h1 class="page-title">Create Admin Account</h1><p class="page-subtitle">Create a new administrator account</p></div>
                </div>
            </div>

            <div class="content-body">
<?php if ($success): ?>
                <div class="alert alert-success"><i class="fas fa-check-circle"></i>
                    <?php $label = (($role ?? 'admin') === 'super_admin') ? 'Super Admin' : 'Admin'; ?>
                    <strong><?php echo $label; ?> account created successfully.</strong> The new <?php echo $label; ?> must <strong>change their password the first time they log in</strong> — they will be taken to a password-change screen automatically.
                </div>
                <?php endif; ?>
                <?php if ($error): ?><div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div><?php endif; ?>

                <div class="card" style="max-width:760px;">
                    <div class="card-header"><h3 class="card-title"><i class="fas fa-user-plus"></i> New Administrator</h3></div>
                    <div class="card-body">
                        <form method="POST" action="" novalidate id="caForm">
                            <?php csrf_token_input(); ?>
                            <div class="ca-grid">
                                <div class="form-group"><label>First Name *</label><input type="text" name="first_name" class="form-control" required placeholder="e.g., Juan"><small id="firstNameStatus" class="ca-status"></small></div>
                                <div class="form-group"><label>Last Name *</label><input type="text" name="last_name" class="form-control" required placeholder="e.g., Dela Cruz"><small id="lastNameStatus" class="ca-status"></small></div>
                                <div class="form-group ca-full"><label>ID Number *</label><input type="text" name="id_number" class="form-control" required placeholder="xxxx-xxxx" maxlength="9" inputmode="numeric"><small id="idNumberStatus" class="ca-status"></small></div>
                                <div class="form-group"><label>Username *</label><input type="text" name="username" class="form-control" required placeholder="8-30 chars, start with letter" autocomplete="off"><small id="usernameStatus" class="ca-status"></small></div>
                                <div class="form-group"><label>Email *</label><input type="email" name="email" class="form-control" required><small id="emailStatus" class="ca-status"></small></div>
                                <div class="form-group"><label>Phone</label><input type="tel" name="phone" class="form-control" placeholder="e.g., 0917-123-4567"><small id="phoneStatus" class="ca-status"></small></div>
                                <div class="form-group"><label>Role *</label>
                                    <select name="role" class="form-control" required>
                                        <option value="admin" <?php echo $role === 'admin' ? 'selected' : ''; ?>>Admin</option>
                                        <option value="super_admin" <?php echo $role === 'super_admin' ? 'selected' : ''; ?>>Super Admin</option>
                                    </select>
                                </div>
                                <div class="form-group"><label>Password *</label><div class="pw-wrap"><input type="password" name="password" class="form-control" required minlength="8" maxlength="30" autocomplete="new-password"><button type="button" class="pw-toggle" onclick="togglePass(this)" tabindex="-1"><i class="fas fa-eye"></i></button></div><small id="passwordStrength" class="ca-status"></small></div>
                                <div class="form-group"><label>Confirm Password *</label><div class="pw-wrap"><input type="password" name="confirm_password" class="form-control" required autocomplete="new-password"><button type="button" class="pw-toggle" onclick="togglePass(this)" tabindex="-1"><i class="fas fa-eye"></i></button></div><small id="confirmStatus" class="ca-status"></small></div>
                            </div>

                            <div class="alert alert-info" style="margin-top:0.75rem;font-size:0.8125rem;"><i class="fas fa-info-circle"></i> After this account is created, the new <?php echo htmlspecialchars(($role ?? 'admin') === 'super_admin' ? 'Super Admin' : 'Admin'); ?> must <strong>change their password</strong> the first time they log in, then add their <strong>security questions</strong> from their own profile.</div>
                            <button type="submit" class="btn btn-primary" style="width:100%;margin-top:0.75rem;"><i class="fas fa-user-plus"></i> Create Account</button>
                        </form>
                        <style>
                            .ca-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:0.5rem 1rem;}
                            .ca-grid .ca-full{grid-column:1/-1;}
                            .ca-grid .form-group{margin-bottom:0.25rem;}
                            .ca-grid .form-group label{font-size:0.75rem;font-weight:600;margin-bottom:0.25rem;display:block;color:var(--text-light);}
                            .ca-grid .form-control{height:34px;font-size:0.8125rem;background:#1a2234;border:1px solid #2e3a52;color:#f1f5f9;color-scheme:dark;}
                            .ca-grid .form-control::placeholder{color:#8fa0b8;opacity:1;}
                            .ca-grid .form-control:focus{border-color:var(--primary);}
                            .ca-status{font-size:0.6875rem;display:block;min-height:0.9em;line-height:1.2;}
                            .pw-wrap{position:relative;}
                            .pw-wrap .form-control{padding-right:2.4rem;}
                            .pw-toggle{position:absolute;right:6px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;color:var(--text-light);padding:2px 5px;font-size:0.85rem;}
                            .pw-toggle:hover{color:var(--primary);}
                            @media(max-width:560px){.ca-grid{grid-template-columns:1fr;}.ca-grid .ca-full{grid-column:1/-1;}}
                        </style>
                        <script>
                        function setStatus(id, msg, ok){ var el=document.getElementById(id); if(el){ el.textContent=msg; el.style.color = ok?'var(--success)':'var(--danger)'; } }
                        function validateName(v,label){ if(!v) return ''; if(v.length<2||v.length>30) return label+' must be 2-30 chars'; if(!/^[A-Z][a-z]+(?: [A-Z][a-z]+)*$/.test(v)) return label+' must start with a capital letter, rest lowercase'; if(/^[A-Z]+$/.test(v)) return label+' cannot be all caps'; if(/[0-9]/.test(v)||/[^A-Za-z\s]/.test(v)) return label+' cannot contain numbers or special characters'; if(/(.)\1{2,}/.test(v)) return label+' cannot have 3+ consecutive identical letters'; return ''; }
                        function checkConfirm(){ var ok=document.getElementsByName('password')[0].value===document.getElementsByName('confirm_password')[0].value&&document.getElementsByName('confirm_password')[0].value.length>0; setStatus('confirmStatus', document.getElementsByName('confirm_password')[0].value?(ok?'Passwords match':'Passwords do not match'):'', ok); }
                        function togglePass(btn){ var inp=btn.closest('.pw-wrap').querySelector('input'); var isPwd=inp.type==='password'; inp.type=isPwd?'text':'password'; btn.querySelector('i').classList.toggle('fa-eye'); btn.querySelector('i').classList.toggle('fa-eye-slash'); }
                        document.getElementsByName('first_name')[0].addEventListener('input',function(){ var v=this.value.trim(),e=validateName(v,'First name'); e?setStatus('firstNameStatus',e,false):setStatus('firstNameStatus','',true); });
                        document.getElementsByName('last_name')[0].addEventListener('input',function(){ var v=this.value.trim(),e=validateName(v,'Last name'); e?setStatus('lastNameStatus',e,false):setStatus('lastNameStatus','',true); });
                        document.getElementsByName('username')[0].addEventListener('input',function(){ var v=this.value.trim(); /^[A-Za-z][A-Za-z0-9_]{7,29}$/.test(v)?setStatus('usernameStatus','Valid',true):setStatus('usernameStatus', v?'Start with letter; 8-30 chars; letters/numbers/_':'', false); });
                        document.getElementsByName('email')[0].addEventListener('input',function(){ var v=this.value.trim(); /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)?setStatus('emailStatus','Valid',true):setStatus('emailStatus', v?'Invalid email':'', false); });
                        document.getElementsByName('phone')[0].addEventListener('input',function(){ var v=this.value.replace(/[^0-9]/g,''); var ok=v.length>=7&&v.length<=15; setStatus('phoneStatus', v?(ok?'Valid number':'7-15 digits'):'', ok); });
                        document.getElementsByName('password')[0].addEventListener('input',function(){ var p=this.value,s=0; if(p.length>=8)s++; if(/[a-z]/.test(p)&&/[A-Z]/.test(p))s++; if(/\d/.test(p))s++; if(/[^A-Za-z0-9]/.test(p))s++; var l=['Weak','Medium','Strong','Very Strong'],c=['var(--danger)','var(--warning)','var(--success)','var(--success)']; setStatus('passwordStrength', p.length?l[Math.max(0,s-1)]:'', true); document.getElementById('passwordStrength').style.color=c[Math.max(0,s-1)]||''; checkConfirm(); });
                        document.getElementsByName('confirm_password')[0].addEventListener('input',checkConfirm);
                        document.getElementsByName('id_number')[0].addEventListener('input',function(){
                            var v = this.value.replace(/[^\d-]/g,'');
                            var d = v.replace(/-/g,'');
                            v = d.length>4 ? d.substring(0,4)+'-'+d.substring(4,8) : d;
                            this.value = v;
                            setStatus('idNumberStatus', /^\d{4}-\d{4}$/.test(v) ? 'Valid format' : (v ? 'Format: xxxx-xxxx' : ''), /^\d{4}-\d{4}$/.test(v));
                        });
                        </script>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div id="sidebarOverlay" class="sidebar-overlay" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('active');"></div>
</body>
</html>
