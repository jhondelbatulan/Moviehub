<?php
require_once __DIR__ . '/functions.php';
require_once __DIR__ . '/csrf.php';

class Auth {
    private $pdo;

    public function __construct($pdo) {
        $this->pdo = $pdo;
    }

    public function login_user($username, $password) {
        try {
            $stmt = $this->pdo->prepare("SELECT id, username, password, first_name, last_name, email, role, account_status, employee_id FROM users WHERE username = ? AND is_deleted = 0");
            $stmt->execute([$username]);
            $user = $stmt->fetch();

            if (!$user || !password_verify($password, $user['password'])) {
                return ['success' => false, 'message' => 'Invalid username or password.'];
            }

            if ($user['account_status'] === STATUS_BLOCKED) {
                return ['success' => false, 'message' => 'Your account has been blocked. Please contact support.'];
            }
            if ($user['account_status'] === STATUS_PENDING) {
                return ['success' => false, 'message' => 'Your account is pending approval. Please wait for an administrator to approve your registration.'];
            }
            if ($user['account_status'] === STATUS_REJECTED) {
                return ['success' => false, 'message' => 'Your registration has been rejected. Please contact support.'];
            }

            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['full_name'] = trim($user['first_name'] . ' ' . $user['last_name']);
            $_SESSION['email'] = $user['email'];
            $_SESSION['user_role'] = $user['role'] ?? 'user';
            $_SESSION['account_status'] = $user['account_status'];
            $_SESSION['employee_id'] = $user['employee_id'] ?? null;

            session_regenerate_id(true);
            log_login($this->pdo, 'users', $user['id'], $user['username'], $_SESSION['full_name'], $user['role'] ?? 'user', 'login', 'success', $user['employee_id']);

            return ['success' => true, 'message' => 'Login successful.'];
        } catch (PDOException $e) {
            error_log("Login error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Database error. Please try again.'];
        }
    }

    public function login_admin($username, $password) {
        try {
            $stmt = $this->pdo->prepare("SELECT id, username, password, full_name, email, role, account_status, employee_id FROM admin_users WHERE username = ? AND is_deleted = 0");
            $stmt->execute([$username]);
            $admin = $stmt->fetch();

            if (!$admin || !password_verify($password, $admin['password'])) {
                return ['success' => false, 'message' => 'Invalid username or password.'];
            }

            if ($admin['account_status'] === STATUS_BLOCKED) {
                return ['success' => false, 'message' => 'Your account has been blocked. Please contact the Super Administrator.'];
            }

            $_SESSION['admin_id'] = $admin['id'];
            $_SESSION['admin_username'] = $admin['username'];
            $_SESSION['admin_full_name'] = $admin['full_name'];
            $_SESSION['admin_email'] = $admin['email'];
            $_SESSION['admin_role'] = $admin['role'];
            $_SESSION['admin_employee_id'] = $admin['employee_id'];
            $_SESSION['account_status'] = $admin['account_status'];

            session_regenerate_id(true);
            log_login($this->pdo, 'admin_users', $admin['id'], $admin['username'], $admin['full_name'], $admin['role'], 'login', 'success', $admin['employee_id']);

            return ['success' => true, 'message' => 'Login successful.', 'role' => $admin['role']];
        } catch (PDOException $e) {
            error_log("Admin login error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Database error. Please try again.'];
        }
    }

    public function logout() {
        if (session_status() === PHP_SESSION_NONE) session_start();

        if (isset($_SESSION['admin_id'])) {
            log_login($this->pdo, 'admin_users', $_SESSION['admin_id'], $_SESSION['admin_username'] ?? '', $_SESSION['admin_full_name'] ?? '', $_SESSION['admin_role'] ?? '', 'logout', 'success', $_SESSION['admin_employee_id'] ?? null);
        } elseif (isset($_SESSION['user_id'])) {
            $stmt = $this->pdo->prepare("SELECT username, CONCAT(first_name, ' ', last_name) as full_name, role, employee_id FROM users WHERE id = ?");
            $stmt->execute([$_SESSION['user_id']]);
            $user = $stmt->fetch();
            if ($user) {
                log_login($this->pdo, 'users', $_SESSION['user_id'], $user['username'], $user['full_name'], $user['role'] ?? 'user', 'logout', 'success', $user['employee_id']);
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
            $stmt = $this->pdo->prepare("SELECT id FROM users WHERE username = ? OR email = ? OR id_number = ?");
            $stmt->execute([$data['username'], $data['email'], $data['id_number']]);
            if ($stmt->fetch()) {
                $stmt2 = $this->pdo->prepare("SELECT id FROM users WHERE id_number = ?");
                $stmt2->execute([$data['id_number']]);
                if ($stmt2->fetch()) return ['success' => false, 'message' => 'ID Number already exists.'];
                return ['success' => false, 'message' => 'Username or email already exists.'];
            }

            $hashed_password = password_hash($data['password'], PASSWORD_DEFAULT);
            $emp_id = generate_employee_id($this->pdo, 'USR');
            $this->pdo->beginTransaction();

            $stmt = $this->pdo->prepare("INSERT INTO users (id_number, employee_id, username, email, password, role, account_status, first_name, middle_initial, last_name, extension_name, sex, birthdate, contact_number, address_street, address_barangay, address_city, address_province, address_country, zip_code) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
            $stmt->execute([
                $data['id_number'], $emp_id, $data['username'], $data['email'],
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
            return ['success' => true, 'message' => 'Registration successful! Your account is pending approval.'];
        } catch (PDOException $e) {
            $this->pdo->rollBack();
            error_log("Registration error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Registration failed. Please try again.'];
        }
    }

    public function register_admin($data, $created_by_role) {
        try {
            if ($created_by_role !== 'super_admin') {
                return ['success' => false, 'message' => 'Only Super Administrators can create admin accounts.'];
            }
            $stmt = $this->pdo->prepare("SELECT id FROM admin_users WHERE username = ? OR email = ?");
            $stmt->execute([$data['username'], $data['email']]);
            if ($stmt->fetch()) return ['success' => false, 'message' => 'Username or email already exists.'];

            $hashed_password = password_hash($data['password'], PASSWORD_DEFAULT);
            $emp_id = generate_employee_id($this->pdo, 'ADM');
            $stmt = $this->pdo->prepare("INSERT INTO admin_users (username, email, password, full_name, role, account_status, employee_id, phone) VALUES (?,?,?,?,?,?,?,?)");
            $stmt->execute([$data['username'], $data['email'], $hashed_password, $data['full_name'], $data['role'] ?? 'admin', STATUS_ACTIVE, $emp_id, $data['phone'] ?? null]);

            return ['success' => true, 'message' => 'Administrator account created successfully.'];
        } catch (PDOException $e) {
            error_log("Admin registration error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Registration failed. Please try again.'];
        }
    }
}
