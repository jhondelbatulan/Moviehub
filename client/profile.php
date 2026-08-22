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

$user = ['username'=>'','email'=>'','first_name'=>'','last_name'=>'','contact_number'=>'','address_street'=>'','profile_picture'=>''];

try {
    $stmt = $pdo->prepare("SELECT id, username, email, first_name, last_name, contact_number, address_street, IFNULL(profile_picture,'') as profile_picture FROM users WHERE id = ? LIMIT 1");
    $stmt->execute([$_SESSION['user_id']]);
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($result) { $user = array_merge($user, $result); }
    else { session_destroy(); header('Location: login.php'); exit(); }
} catch (PDOException $e) { error_log('Profile Error: '.$e->getMessage()); $error = 'Unable to retrieve user information.'; }

$display_full_name = trim($user['first_name'].' '.$user['last_name']);

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token. Please try again.';
    } else {
        $email = trim($_POST['email']);
        $full_name = trim($_POST['full_name']);
        $contact_number = trim($_POST['contact_number']);
        $address_street = trim($_POST['address']);
        $new_password = $_POST['new_password'];
        $confirm_password = $_POST['confirm_password'];

        if (empty($email) || empty($full_name)) { $error = 'Email and Full Name are required.'; }
        elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) { $error = 'Please enter a valid email.'; }
        else {
            try {
                $pdo->beginTransaction();
                $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ? AND id != ?");
                $stmt->execute([$email, $_SESSION['user_id']]);
                if ($stmt->fetch()) throw new Exception('Email already taken.');

                $name_parts = preg_split('/\s+/', $full_name, 2);
                $fn = ucfirst(strtolower($name_parts[0] ?? ''));
                $ln = isset($name_parts[1]) ? ucfirst(strtolower($name_parts[1])) : '';

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

                $sql = "UPDATE users SET email=:email, first_name=:fn, last_name=:ln, contact_number=:cn, address_street=:addr, profile_picture=:pic";
                $params = [':email'=>$email, ':fn'=>$fn, ':ln'=>$ln, ':cn'=>$contact_number, ':addr'=>$address_street, ':pic'=>$pic];
                if (!empty($new_password)) {
                    if ($new_password !== $confirm_password) throw new Exception('Passwords do not match.');
                    if (strlen($new_password) < 8) throw new Exception('Password must be at least 8 characters.');
                    $sql .= ", password=:pwd";
                    $params[':pwd'] = password_hash($new_password, PASSWORD_DEFAULT);
                }
                $sql .= " WHERE id=:id";
                $params[':id'] = $_SESSION['user_id'];
                $stmt = $pdo->prepare($sql);
                $stmt->execute($params);
                $pdo->commit();
                $_SESSION['full_name'] = $fn.' '.$ln;
                $display_full_name = $_SESSION['full_name'];
                $success = 'Profile updated successfully!';
                $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
                $stmt->execute([$_SESSION['user_id']]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
            } catch (Exception $e) {
                $pdo->rollBack();
                $error = $e->getMessage();
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
                <p class="page-subtitle">Manage your account settings</p>
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
                            <div class="avatar avatar-xl"><?php echo strtoupper(substr($_SESSION['full_name'], 0, 1)); ?></div>
                        <?php endif; ?>
                    </div>
                    <div class="profile-info">
                        <h2><?php echo htmlspecialchars($display_full_name); ?></h2>
                        <p><i class="fas fa-user"></i> <?php echo htmlspecialchars($user['username']); ?></p>
                        <p><i class="fas fa-envelope"></i> <?php echo htmlspecialchars($user['email']); ?></p>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header"><h3 class="card-title"><i class="fas fa-user-edit"></i> Edit Profile</h3></div>
                    <div class="card-body">
                        <form method="POST" action="" enctype="multipart/form-data">
                            <?php csrf_token_input(); ?>
                            <div class="form-row">
                                <div class="form-group">
                                    <label>Username</label>
                                    <input type="text" class="form-control" value="<?php echo htmlspecialchars($user['username']); ?>" readonly style="background:var(--background);">
                                    <small class="form-text">Username cannot be changed</small>
                                </div>
                                <div class="form-group">
                                    <label>Email *</label>
                                    <input type="email" name="email" class="form-control" required value="<?php echo htmlspecialchars($user['email']); ?>">
                                </div>
                            </div>
                            <div class="form-row">
                                <div class="form-group">
                                    <label>Full Name *</label>
                                    <input type="text" name="full_name" class="form-control" required value="<?php echo htmlspecialchars($display_full_name); ?>">
                                </div>
                                <div class="form-group">
                                    <label>Contact Number</label>
                                    <input type="tel" name="contact_number" class="form-control" value="<?php echo htmlspecialchars($user['contact_number']); ?>">
                                </div>
                            </div>
                            <div class="form-group">
                                <label>Address</label>
                                <textarea name="address" class="form-control" rows="2"><?php echo htmlspecialchars($user['address_street']); ?></textarea>
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

                            <div class="divider"></div>
                            <h4 style="margin-bottom:1rem;"><i class="fas fa-lock"></i> Change Password (Optional)</h4>
                            <div class="form-row">
                                <div class="form-group">
                                    <label>New Password</label>
                                    <input type="password" id="new_password" name="new_password" class="form-control" minlength="8">
                                </div>
                                <div class="form-group">
                                    <label>Confirm New Password</label>
                                    <input type="password" id="confirm_password" name="confirm_password" class="form-control" minlength="8">
                                </div>
                            </div>

                            <button type="submit" class="btn btn-primary" style="width:100%;"><i class="fas fa-save"></i> Update Profile</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </main>
    <script>
        document.getElementById('confirm_password').addEventListener('input', function() {
            var np = document.getElementById('new_password').value;
            this.setCustomValidity(np && this.value !== np ? 'Passwords do not match' : '');
        });
    </script>
</body>
</html>
