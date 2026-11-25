<?php
require_once __DIR__ . '/functions.php';
require_once __DIR__ . '/csrf.php';
require_once __DIR__ . '/otp.php';

class Auth {
    private $pdo;

    public function __construct($pdo) {
        $this->pdo = $pdo;
    }

    public function login_user($username, $password) {
        try {
            $stmt = $this->pdo->prepare("SELECT id, username, password, first_name, last_name, email, role, account_status, id_number, must_change_password FROM users WHERE (username = ? OR id_number = ?) AND is_deleted = 0");
            $stmt->execute([$username, $username]);
            $user = $stmt->fetch();

            if (!$user || !password_verify($password, $user['password'])) {
                log_audit($this->pdo, 'login_failed', 'users', null, null, 'Failed login attempt for "' . $username . '"');
                return ['success' => false, 'message' => 'Invalid username/ID or password.'];
            }

            if ($user['account_status'] === STATUS_BLOCKED) {
                return ['success' => false, 'message' => 'Account is blocked'];
            }
            if ($user['account_status'] === STATUS_PENDING) {
                return ['success' => false, 'message' => 'Your account is pending approval. Please wait for an administrator to approve your registration.'];
            }
            if ($user['account_status'] === STATUS_REJECTED) {
                return ['success' => false, 'message' => 'Your registration has been rejected. Please contact support.'];
            }

            // Logout sets this to offline; mark the account online before the
            // dashboard's active-status check runs on the next login.
            $status_stmt = $this->pdo->prepare("UPDATE users SET account_status = 'online' WHERE id = ? AND account_status IN ('approved', 'active', 'offline', 'online')");
            $status_stmt->execute([$user['id']]);

            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['full_name'] = trim($user['first_name'] . ' ' . $user['last_name']);
            $_SESSION['email'] = $user['email'];
            $_SESSION['user_role'] = $user['role'] ?? 'user';
            $_SESSION['account_status'] = 'online';
            $_SESSION['id_number'] = $user['id_number'] ?? null;
            $_SESSION['must_change_password'] = (int)($user['must_change_password'] ?? 0);
            $_SESSION['last_activity'] = time();
            session_regenerate_id(true);
            log_login($this->pdo, 'users', $user['id'], $user['username'], $_SESSION['full_name'], $_SESSION['user_role'], 'login', 'success', $user['id_number'] ?? null);
            log_audit($this->pdo, 'login', 'users', $user['id'], $_SESSION['full_name'], 'User logged in');
            $_SESSION['login_attempts'] = 0;
            $_SESSION['lockout_until'] = 0;

            return ['success' => true, 'message' => 'Login successful.', 'role' => $_SESSION['user_role']];
        } catch (PDOException $e) {
            error_log("Login error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Database error. Please try again.'];
        }
    }

    public function login_admin($username, $password) {
        try {
$stmt = $this->pdo->prepare("SELECT id, username, password, full_name, email, role, account_status, id_number, must_change_password, last_login FROM admin_users WHERE (username = ? OR id_number = ?) AND is_deleted = 0");
            $stmt->execute([$username, $username]);
            $admin = $stmt->fetch();

            if (!$admin) {
                $pstmt = $this->pdo->prepare("SELECT id, id_number, username, password, full_name, email, phone, role FROM pending_admin_accounts WHERE username = ? OR id_number = ?");
                $pstmt->execute([$username, $username]);
                $pending = $pstmt->fetch();

                if (!$pending || !password_verify($password, $pending['password'])) {
                    log_audit($this->pdo, 'login_failed', 'admin_users', null, null, 'Failed login attempt for "' . $username . '"');
                    return ['success' => false, 'message' => 'Invalid username or password.'];
                }

                $_SESSION['pending_admin_setup'] = true;
                $_SESSION['pending_admin_data'] = [
                    'username' => $pending['username'],
                    'full_name' => $pending['full_name'],
                    'email' => $pending['email'],
                    'phone' => $pending['phone'],
                    'id_number' => $pending['id_number'],
                    'role' => $pending['role'],
                ];
                $_SESSION['last_activity'] = time();
                log_audit($this->pdo, 'login', 'admin_users', null, $pending['full_name'], 'Pending admin first login (setup pending)');

                return ['success' => true, 'message' => 'Login successful. Please complete your account setup.', 'role' => $pending['role'], 'pending_setup' => true];
            }

            if ($admin['account_status'] === STATUS_BLOCKED) {
                return ['success' => false, 'message' => 'Account is blocked'];
            }

            if ($admin['account_status'] === 'inactive') {
                return ['success' => false, 'message' => 'Account is inactive'];
            }

            if (!password_verify($password, $admin['password'])) {
                log_audit($this->pdo, 'login_failed', 'admin_users', null, null, 'Failed login attempt for "' . $username . '"');
                return ['success' => false, 'message' => 'Invalid username or password.'];
            }

            $is_first_login = ($admin['last_login'] === null);

            $stmt = $this->pdo->prepare("UPDATE admin_users SET last_login = NOW() WHERE id = ?");
            $stmt->execute([$admin['id']]);

            $_SESSION['admin_id'] = $admin['id'];
            $_SESSION['admin_username'] = $admin['username'];
            $_SESSION['admin_full_name'] = $admin['full_name'];
            $_SESSION['admin_email'] = $admin['email'];
            $_SESSION['admin_role'] = $admin['role'];
            $_SESSION['admin_id_number'] = $admin['id_number'];
            $_SESSION['account_status'] = $admin['account_status'];
$_SESSION['must_change_password'] = (int)($admin['must_change_password'] ?? 0);

            if ($is_first_login) {
                $_SESSION['show_edit_profile_notice'] = true;
            }

session_regenerate_id(true);
            log_login($this->pdo, 'admin_users', $admin['id'], $admin['username'], $admin['full_name'], $admin['role'], 'login', 'success', $admin['id_number']);
            log_audit($this->pdo, 'login', 'admin_users', $admin['id'], $admin['full_name'], 'Admin logged in');

            return ['success' => true, 'message' => 'Login successful.', 'role' => $admin['role']];
        } catch (PDOException $e) {
            error_log("Admin login error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Database error. Please try again.'];
        }
    }

public function login_pending_user($username, $password) {
        try {
            $stmt = $this->pdo->prepare("SELECT id, id_number, username, password, email, role, created_by_admin_id, created_by_name FROM pending_user_accounts WHERE username = ? OR id_number = ?");
            $stmt->execute([$username, $username]);
            $pending = $stmt->fetch();

            if (!$pending || !password_verify($password, $pending['password'])) {
                log_audit($this->pdo, 'login_failed', 'users', null, null, 'Failed login attempt for "' . $username . '" (pending user)');
                return ['success' => false, 'message' => 'Invalid username or password.'];
            }

            $_SESSION['pending_user_setup'] = true;
            $_SESSION['pending_user_data'] = [
                'username' => $pending['username'],
                'email' => $pending['email'],
                'id_number' => $pending['id_number'],
                'role' => $pending['role'] ?? 'user',
            ];
            $_SESSION['last_activity'] = time();
            log_audit($this->pdo, 'login', 'users', null, $pending['username'], 'Pending user first login (setup pending)');

            return ['success' => true, 'message' => 'Login successful. Please complete your account setup.', 'role' => $pending['role'] ?? 'user', 'pending_setup' => true];
        } catch (PDOException $e) {
            error_log("Pending user login error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Database error. Please try again.'];
        }
    }

    public function logout() {
        if (session_status() === PHP_SESSION_NONE) session_start();

        if (isset($_SESSION['admin_id'])) {
            log_login($this->pdo, 'admin_users', $_SESSION['admin_id'], $_SESSION['admin_username'] ?? '', $_SESSION['admin_full_name'] ?? '', $_SESSION['admin_role'] ?? '', 'logout', 'success', $_SESSION['admin_id_number'] ?? null);
            log_audit($this->pdo, 'logout', 'admin_users', $_SESSION['admin_id'], $_SESSION['admin_full_name'] ?? '', 'Admin logged out');
        } elseif (isset($_SESSION['user_id'])) {
            $stmt = $this->pdo->prepare("SELECT username, CONCAT(first_name, ' ', last_name) as full_name, role, id_number FROM users WHERE id = ?");
            $stmt->execute([$_SESSION['user_id']]);
            $user = $stmt->fetch();
            if ($user) {
                $stmt = $this->pdo->prepare("UPDATE users SET account_status = 'offline' WHERE id = ? AND account_status IN ('online','approved','active')");
                $stmt->execute([$_SESSION['user_id']]);
                log_login($this->pdo, 'users', $_SESSION['user_id'], $user['username'], $user['full_name'], $user['role'] ?? 'user', 'logout', 'success', $user['id_number']);
                log_audit($this->pdo, 'logout', 'users', $_SESSION['user_id'], $user['full_name'], 'User logged out');
            }
        }

        $_SESSION = [];
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $params["path"], $params["domain"], $params["secure"], $params["httponly"]);
        }
        session_destroy();
        session_start();
    }

    public function register_user($data) {
        try {
            if (username_taken($this->pdo, $data['username'] ?? '')) {
                return ['success' => false, 'message' => 'Username already taken. Please choose a different username.'];
            }
            if (email_taken($this->pdo, $data['email'] ?? '')) {
                return ['success' => false, 'message' => 'Email address is already in use. Please choose another email.'];
            }
            $stmt = $this->pdo->prepare("SELECT id FROM users WHERE username = ? OR email = ? OR id_number = ?");
            $stmt->execute([$data['username'], $data['email'], $data['id_number']]);
            if ($stmt->fetch()) {
                $stmt2 = $this->pdo->prepare("SELECT id FROM users WHERE id_number = ?");
                $stmt2->execute([$data['id_number']]);
                if ($stmt2->fetch()) return ['success' => false, 'message' => 'ID Number already exists.'];
                return ['success' => false, 'message' => 'Username or email already exists.'];
            }

$hashed_password = password_hash($data['password'], PASSWORD_DEFAULT);
            $this->pdo->beginTransaction();

            $stmt = $this->pdo->prepare("INSERT INTO users (id_number, username, email, password, role, account_status, first_name, middle_initial, last_name, extension_name, sex, birthdate, contact_number, address_street, address_barangay, address_city, address_province, address_country, zip_code) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
            $stmt->execute([
                $data['id_number'], $data['username'], $data['email'],
                $hashed_password, 'user', STATUS_PENDING,
                ucfirst(strtolower($data['first_name'])),
                !empty($data['middle_initial']) ? strtoupper(substr($data['middle_initial'], 0, 1)) : null,
                ucfirst(strtolower($data['last_name'])),
                $data['extension_name'] ?: null, $data['sex'], $data['birthdate'], $data['contact_number'],
                ucwords(strtolower($data['address_street'] ?? '')), ucwords(strtolower($data['address_barangay'] ?? '')),
                ucwords(strtolower($data['address_city'] ?? '')), ucwords(strtolower($data['address_province'] ?? '')),
                ucwords(strtolower($data['address_country'] ?? '')), $data['zip_code'] ?? ''
            ]);

            $user_id = $this->pdo->lastInsertId();
            $stmt = $this->pdo->prepare("INSERT INTO registration_approvals (user_id, status) VALUES (?, ?)");
            $stmt->execute([$user_id, STATUS_PENDING]);

            if (!empty($data['security_questions']) && is_array($data['security_questions'])) {
                foreach ($data['security_questions'] as $sq) {
                    $question_id = $sq['question_id'];
                    $answer = strtolower(trim($sq['answer']));
                    $answer_hash = password_hash($answer, PASSWORD_DEFAULT);
                    $stmt = $this->pdo->prepare("INSERT INTO security_answers (user_table, user_id, question_id, answer_hash) VALUES ('users', ?, ?, ?)");
                    $stmt->execute([$user_id, $question_id, $answer_hash]);
                }
            }

$this->pdo->commit();
            log_audit($this->pdo, 'register', 'users', $user_id, $data['username'], 'New user registration submitted (pending approval)');
            return ['success' => true, 'message' => 'Registration successful! Your account is pending approval.'];
        } catch (PDOException $e) {
            $this->pdo->rollBack();
            error_log("Registration error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Registration failed. Please try again.'];
        }
    }

public function create_account($data, $created_by_role = null, $created_by_id = null, $created_by_name = '') {
        $super_admin_creation_lock = false;
        try {
            if ($created_by_role !== 'super_admin') {
                return ['success' => false, 'message' => 'Only Super Administrators can create accounts.'];
            }

            $role = $data['role'] ?? '';
            $id_number = $data['id_number'] ?? '';
            $username = $data['username'] ?? '';
            $email = $data['email'] ?? '';
            $password = $data['password'] ?? '';

            if (!in_array($role, ['admin', 'super_admin', 'user'], true)) {
                return ['success' => false, 'message' => 'Invalid role.'];
            }

            if ($role === 'super_admin') {
                $lock = $this->pdo->query("SELECT GET_LOCK('moviehub_super_admin_account_creation', 5)")->fetchColumn();
                if ((int)$lock !== 1) {
                    return ['success' => false, 'message' => 'Super Admin account creation is busy. Please try again.'];
                }
                $super_admin_creation_lock = true;
                if (count_super_admin_accounts($this->pdo) >= 2) {
                    return ['success' => false, 'message' => 'The maximum of 2 Super Admin accounts has already been reached.'];
                }
            }

            $password_error = validate_strong_password($password);
            if ($password_error !== '') {
                return ['success' => false, 'message' => $password_error];
            }

            if (username_taken($this->pdo, $username)) {
                return ['success' => false, 'message' => 'Username already taken. Please choose a different username.'];
            }
            if (email_taken($this->pdo, $email)) {
                return ['success' => false, 'message' => 'Email address is already in use. Please choose another email.'];
            }

            if ($role === 'user') {
                $stmt = $this->pdo->prepare("SELECT id FROM users WHERE username = ? OR email = ? OR id_number = ?");
                $stmt->execute([$username, $email, $id_number]);
                if ($stmt->fetch()) return ['success' => false, 'message' => 'Username, email, or ID number already exists.'];
                $stmt = $this->pdo->prepare("SELECT id FROM admin_users WHERE id_number = ?");
                $stmt->execute([$id_number]);
                if ($stmt->fetch()) return ['success' => false, 'message' => 'ID number is already in use by an admin account.'];
                $stmt = $this->pdo->prepare("SELECT id FROM pending_admin_accounts WHERE id_number = ?");
                $stmt->execute([$id_number]);
                if ($stmt->fetch()) return ['success' => false, 'message' => 'ID number is reserved by a pending admin account.'];
                $stmt = $this->pdo->prepare("SELECT id FROM pending_user_accounts WHERE username = ? OR email = ? OR id_number = ?");
                $stmt->execute([$username, $email, $id_number]);
                if ($stmt->fetch()) return ['success' => false, 'message' => 'Username, email, or ID number is reserved by a pending user account.'];

                $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                $stmt = $this->pdo->prepare("INSERT INTO pending_user_accounts (id_number, username, email, password, role, created_by_admin_id, created_by_name) VALUES (?,?,?,?,?,?,?)");
                $stmt->execute([$id_number, $username, $email, $hashed_password, 'user', $created_by_id, $created_by_name]);
                $new_id = $this->pdo->lastInsertId();
                log_audit($this->pdo, 'register', 'users', $new_id, $username, 'User account created by Super Administrator (stored as pending; activated on first-login setup)');
            } else {
                $stmt = $this->pdo->prepare("SELECT id FROM admin_users WHERE username = ? OR email = ? OR id_number = ?");
                $stmt->execute([$username, $email, $id_number]);
                if ($stmt->fetch()) return ['success' => false, 'message' => 'Username, email, or ID number already exists.'];
                $stmt = $this->pdo->prepare("SELECT id FROM users WHERE id_number = ?");
                $stmt->execute([$id_number]);
                if ($stmt->fetch()) return ['success' => false, 'message' => 'ID number is already in use by a user account.'];
                $stmt = $this->pdo->prepare("SELECT id FROM pending_admin_accounts WHERE username = ? OR email = ? OR id_number = ?");
                $stmt->execute([$username, $email, $id_number]);
                if ($stmt->fetch()) return ['success' => false, 'message' => 'Username, email, or ID number is reserved by a pending admin account.'];
                $stmt = $this->pdo->prepare("SELECT id FROM pending_user_accounts WHERE id_number = ? OR username = ? OR email = ?");
                $stmt->execute([$id_number, $username, $email]);
                if ($stmt->fetch()) return ['success' => false, 'message' => 'Username, email, or ID number is reserved by a pending user account.'];

                $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                $stmt = $this->pdo->prepare("INSERT INTO pending_admin_accounts (id_number, username, email, password, full_name, role, created_by_admin_id, created_by_name) VALUES (?,?,?,?,?,?,?,?)");
                $stmt->execute([$id_number, $username, $email, $hashed_password, '', $role, $created_by_id, $created_by_name]);
                $new_id = $this->pdo->lastInsertId();
                log_audit($this->pdo, 'register', 'admin_users', $new_id, $username, 'Admin account created by Super Administrator with role ' . $role . ' (stored as pending; becomes inactive on first-login setup and requires activation)');
            }

            return [
                'success' => true,
                'message' => 'Account created successfully and stored as a pending account. It will be saved into the account management tables only after the new account completes its first-login setup (new password + security questions), and will remain inactive until an administrator activates it.',
                'role' => $role,
                'username' => $username,
            ];
        } catch (PDOException $e) {
            error_log("Account creation error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Registration failed. Please try again.'];
        } finally {
            if ($super_admin_creation_lock) {
                try { $this->pdo->query("SELECT RELEASE_LOCK('moviehub_super_admin_account_creation')"); }
                catch (PDOException $e) { error_log('Failed to release super admin account creation lock: ' . $e->getMessage()); }
            }
        }
    }
}
