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

$user_id = $_SESSION['reset_verified_user_id'];
$user_table = $_SESSION['reset_verified_user_table'] ?? 'users';

try {
    if ($user_table === 'admin_users') {
        $stmt = $pdo->prepare('SELECT full_name FROM admin_users WHERE id = ? AND is_deleted = 0');
        $stmt->execute([$user_id]);
    } else {
        $stmt = $pdo->prepare('SELECT first_name, last_name FROM users WHERE id = ? AND is_deleted = 0');
        $stmt->execute([$user_id]);
    }
    $user = $stmt->fetch();
    if (!$user) { header('Location: forgot_password.php'); exit(); }

    $stmt = $pdo->prepare('SELECT sa.question_id AS id, sq.question_text FROM security_answers sa JOIN secret_questions sq ON sq.id = sa.question_id WHERE sa.user_table = ? AND sa.user_id = ? ORDER BY sa.id LIMIT 3');
    $stmt->execute([$user_table, $user_id]);
    $registeredQuestions = $stmt->fetchAll(PDO::FETCH_ASSOC);
    if (count($registeredQuestions) !== 3) { header('Location: forgot_password.php'); exit(); }
} catch (PDOException $e) {
    header('Location: forgot_password.php');
    exit();
}

$error = '';
$success = '';
$old_q = [$_POST['q1'] ?? '', $_POST['q2'] ?? '', $_POST['q3'] ?? ''];
$old_a = [$_POST['a1'] ?? '', $_POST['a2'] ?? '', $_POST['a3'] ?? ''];

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token.';
    } else {
        $question_ids = array_map('intval', array_filter([$_POST['q1'] ?? '', $_POST['q2'] ?? '', $_POST['q3'] ?? ''], function ($v) { return $v !== ''; }));
        $answers = [trim($_POST['a1'] ?? ''), trim($_POST['a2'] ?? ''), trim($_POST['a3'] ?? '')];

        $registered_ids = array_map('intval', array_column($registeredQuestions, 'id'));
        if ($question_ids !== $registered_ids) {
            $error = 'Please answer the three security questions registered to your account.';
        } else {
            $placeholders = implode(',', array_fill(0, count($question_ids), '?'));
            $stmt3 = $pdo->prepare('SELECT question_id, answer_hash FROM security_answers WHERE user_table = ? AND user_id = ? AND question_id IN (' . $placeholders . ')');
            $stmt3->execute(array_merge([$user_table, $user_id], $question_ids));
            $records = [];
            foreach ($stmt3->fetchAll(PDO::FETCH_ASSOC) as $r) {
                $records[$r['question_id']] = $r['answer_hash'];
            }

            $correct_count = 0;
            foreach ($question_ids as $i => $qid) {
                if (isset($records[$qid]) && $answers[$i] !== '' && password_verify(strtolower($answers[$i]), $records[$qid])) {
                    $correct_count++;
                }
            }

            if ($correct_count >= SECRET_QUESTIONS_MIN_CORRECT) {
                $_SESSION['security_verified'] = true;
                header('Location: reset_password_form.php');
                exit();
            } else {
                $error = 'Your answers did not match enough of your registered questions. You need at least ' . SECRET_QUESTIONS_MIN_CORRECT . ' correct answers to proceed.';
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
    <title>Security Questions - MovieHub</title>
    <link rel="stylesheet" href="../assets/css/style.css?v=2.3.0">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        html,body{height:100%;margin:0;padding:0;}
        body{overflow:auto;}
        .sq-wrapper{min-height:100vh;display:flex;flex-direction:column;}
        .sq-wrapper header{flex-shrink:0;}
        .sq-main{flex:1;display:flex;align-items:center;justify-content:center;padding:1rem;background:rgba(0,0,0,0.4);}
        .sq-card{background:var(--surface);border-radius:var(--radius-xl);box-shadow:var(--shadow-lg);width:100%;max-width:520px;border:1px solid var(--border);overflow:hidden;}
        .sq-header{text-align:center;padding:1.5rem 1.5rem 0.5rem;}
        .sq-header h2{font-size:1.25rem;margin:0;}
        .sq-header p{color:var(--text-light);font-size:0.8125rem;margin:0.25rem 0 0;}
        .sq-step-ind{display:flex;justify-content:center;gap:0;padding:0.75rem 1.5rem 0;}
        .sq-step{display:flex;align-items:center;gap:0.5rem;font-size:0.8125rem;font-weight:500;color:var(--muted);}
        .sq-step.done{color:var(--success);}
        .sq-step.active{color:var(--primary);}
        .sq-step .sn{width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:0.75rem;font-weight:600;background:var(--background);color:var(--muted);border:2px solid var(--border);}
        .sq-step.done .sn{background:var(--success-bg);color:var(--success);border-color:var(--success);}
        .sq-step.active .sn{background:var(--primary);color:white;border-color:var(--primary);}
        .sq-body{padding:1rem 1.5rem;}
        .sq-item{background:var(--background);border-radius:var(--radius);padding:0.75rem 1rem;margin-bottom:0.75rem;border:1px solid var(--border);}
        .sq-item label{font-size:0.8125rem;font-weight:600;color:var(--text);display:block;margin-bottom:0.375rem;}
        .sq-item label i{color:var(--primary);margin-right:0.25rem;}
        .sq-item input{height:36px;font-size:0.875rem;}
        .sq-footer{padding:0 1.5rem 1.5rem;display:flex;gap:0.5rem;}
        .sq-footer .btn{flex:1;}
        .sq-links{text-align:center;padding:0 1.5rem 1rem;font-size:0.8125rem;color:var(--text-light);}
        .sq-links a{color:var(--primary);}
    </style>
</head>
<body style="background: url('../assets/homepage.jpg') center/cover no-repeat fixed; background-color: #1a1a2e;">
    <?php require_once '../includes/header_public.php'; ?>

    <div class="sq-wrapper">
        <main class="sq-main">
            <div class="sq-card">
                <div class="sq-header">
                    <h2><i class="fas fa-shield-alt" style="color:var(--primary);"></i> Security Questions</h2>
                            <p>OTP verified. Answer the three security questions you registered during sign-up. You need at least <?php echo SECRET_QUESTIONS_MIN_CORRECT; ?> correct.</p>
                </div>

                <div class="sq-step-ind">
                    <div class="sq-step done"><div class="sn"><i class="fas fa-check" style="font-size:10px;"></i></div> OTP Verified</div>
                    <div style="width:40px;height:2px;background:var(--border);margin:0 0.5rem;align-self:center;"></div>
                    <div class="sq-step active"><div class="sn">2</div> Security Questions</div>
                    <div style="width:40px;height:2px;background:var(--border);margin:0 0.5rem;align-self:center;"></div>
                    <div class="sq-step"><div class="sn">3</div> New Password</div>
                </div>

                <?php if (!empty($_SESSION['reset_masked_id_number']) || !empty($_SESSION['reset_masked_email'])): ?>
                <div class="alert alert-info" style="margin:0.75rem 1.5rem 0;font-size:0.8125rem;display:flex;flex-direction:column;gap:0.25rem;">
                    <?php if (!empty($_SESSION['reset_masked_id_number'])): ?><span><i class="fas fa-id-card"></i> ID Number: <strong><?php echo htmlspecialchars($_SESSION['reset_masked_id_number']); ?></strong></span><?php endif; ?>
                    <?php if (!empty($_SESSION['reset_masked_email'])): ?><span><i class="fas fa-envelope"></i> Email: <strong><?php echo htmlspecialchars($_SESSION['reset_masked_email']); ?></strong></span><?php endif; ?>
                </div>
                <?php endif; ?>

                <?php if ($error): ?>
                    <div class="alert alert-danger" style="margin:0.75rem 1.5rem 0;"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div>
                <?php endif; ?>

                <form method="POST" action="" class="sq-body">
                    <?php csrf_token_input(); ?>

                    <?php for ($i = 1; $i <= 3; $i++): ?>
                    <div class="sq-item">
                        <label><i class="fas fa-question-circle"></i> Question <?php echo $i; ?></label>
                        <div class="form-control" style="height:auto;min-height:36px;margin-bottom:0.5rem;background:var(--surface);display:flex;align-items:center;"><?php echo htmlspecialchars($registeredQuestions[$i - 1]['question_text']); ?></div>
                        <input type="hidden" name="q<?php echo $i; ?>" value="<?php echo (int)$registeredQuestions[$i - 1]['id']; ?>">
                        <div style="position:relative;">
                            <input type="password" name="a<?php echo $i; ?>" class="form-control" placeholder="Your answer" value="<?php echo htmlspecialchars($old_a[$i-1]); ?>" style="padding-right:2.5rem;" required>
                            <button type="button" onclick="toggleSq(this)" style="position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;color:var(--muted);"><i class="fas fa-eye"></i></button>
                        </div>
                    </div>
                    <?php endfor; ?>

                    <small style="display:block;text-align:center;color:var(--text-light);font-size:0.75rem;margin-bottom:1rem;">
                        You need at least <?php echo SECRET_QUESTIONS_MIN_CORRECT; ?> correct answers out of 3.
                    </small>

                    <div class="sq-footer">
                        <a href="verify_otp.php" class="btn btn-outline"><i class="fas fa-arrow-left"></i> Back</a>
                        <button type="submit" class="btn btn-primary"><i class="fas fa-check"></i> Verify Answers</button>
                    </div>
                </form>

                <div class="sq-links"><a href="login.php"><i class="fas fa-arrow-left"></i> Back to Login</a></div>
            </div>
        </main>
        <footer style="flex-shrink:0;padding:0.5rem;text-align:center;color:rgba(255,255,255,0.7);font-size:0.75rem;border:none;"><p style="margin:0;padding:0;border:none;">&copy; <?php echo date('Y'); ?> MovieHub. All rights reserved.</p></footer>
    </div>

    <script>
    function toggleSq(btn) {
        var inp = btn.previousElementSibling;
        var isPwd = inp.type === 'password';
        inp.type = isPwd ? 'text' : 'password';
        btn.querySelector('i').classList.toggle('fa-eye');
        btn.querySelector('i').classList.toggle('fa-eye-slash');
    }
    </script>
</body>
</html>
