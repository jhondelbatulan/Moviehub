<?php
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/functions.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

function send_otp_email($email, $otp, $full_name = '', $purpose = 'password_reset') {
    if (!EMAIL_ENABLED) {
        error_log("[OTP] Email disabled. OTP for $email: $otp");
        return true;
    }

    $name = $full_name ?: 'User';
    $is_login = ($purpose === 'login');
    $is_registration = ($purpose === 'verification');
    if ($is_registration) {
        $subject = SITE_NAME . ' - Verify Your Email Address';
        $introLine = 'Welcome to ' . SITE_NAME . '! Use the code below to verify your email address. Your account will be submitted for approval after verification:';
    } elseif ($is_login) {
        $subject = SITE_NAME . ' - Login Verification Code';
        $introLine = 'Your login is almost complete. Use the code below to verify your identity and sign in to your account:';
    } else {
        $subject = SITE_NAME . ' - Your One-Time Password';
        $introLine = 'You requested a One-Time Password (OTP) for password reset. Use the code below:';
    }

    $htmlBody  = '<div style="font-family:Inter,Arial,sans-serif;max-width:480px;margin:auto;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden;">';
    $htmlBody .= '<div style="background:#059669;padding:24px 32px;text-align:center;"><h1 style="color:#fff;margin:0;font-size:22px;">' . SITE_NAME . '</h1></div>';
    $htmlBody .= '<div style="padding:32px;">';
    $htmlBody .= '<p style="font-size:15px;color:#374151;">Hello <strong>' . htmlspecialchars($name) . '</strong>,</p>';
    $htmlBody .= '<p style="font-size:15px;color:#374151;">' . $introLine . '</p>';
    $htmlBody .= '<div style="background:#f9fafb;border:1px dashed #059669;border-radius:8px;padding:20px;text-align:center;margin:24px 0;">';
    $htmlBody .= '<span style="font-size:32px;font-weight:700;letter-spacing:8px;color:#059669;font-family:monospace;">' . $otp . '</span>';
    $htmlBody .= '</div>';
    $htmlBody .= '<p style="font-size:13px;color:#6b7280;">This code will expire in <strong>' . OTP_EXPIRY_MINUTES . ' minutes</strong>.</p>';
    $htmlBody .= '<p style="font-size:13px;color:#6b7280;">If you did not request this, please ignore this email.</p>';
    $htmlBody .= '</div>';
    $htmlBody .= '<div style="background:#f9fafb;padding:16px 32px;text-align:center;border-top:1px solid #e5e7eb;"><p style="font-size:12px;color:#9ca3af;margin:0;">&copy; ' . date('Y') . ' ' . SITE_NAME . ' &mdash; All rights reserved.</p></div>';
    $htmlBody .= '</div>';

    $textBody = "Hello $name,\n\n$introLine\n\n$otp\n\nThis code expires in " . OTP_EXPIRY_MINUTES . " minutes.\nIf you did not request this, ignore this email.\n\n" . SITE_NAME . " Team";

    $mail = new PHPMailer(true);
    try {
        $mail->isSMTP();
        $mail->Host       = SMTP_HOST;
        $mail->SMTPAuth   = true;
        $mail->Username   = SMTP_USERNAME;
        $mail->Password   = SMTP_PASSWORD;
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = SMTP_PORT;
        $mail->CharSet    = 'UTF-8';

        $mail->setFrom(SMTP_FROM_EMAIL, SMTP_FROM_NAME);
        $mail->addAddress($email, $name);
        $mail->isHTML(true);
        $mail->Subject = $subject;
        $mail->Body    = $htmlBody;
        $mail->AltBody = $textBody;

        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log("[OTP] PHPMailer error for $email: " . $mail->ErrorInfo);
        return false;
    }
}

function send_account_credentials_email($email, $username, $password, $role = 'user') {
    if (!EMAIL_ENABLED) {
        error_log("[Account] Email disabled. Credentials for $email — username: $username, password: $password");
        return true;
    }

    $role_label = ucfirst(str_replace('_', ' ', $role));
    $subject = SITE_NAME . ' - Your Account Credentials';

    $login_url = rtrim(SITE_URL, '/') . '/client/login.php';
    $htmlBody  = '<div style="font-family:Inter,Arial,sans-serif;max-width:520px;margin:auto;background-color:#ffffff;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden;">';
    $htmlBody .= '<div style="background:linear-gradient(135deg,#059669,#0d9488);padding:28px 36px;text-align:center;"><span style="color:#ffffff;font-size:26px;font-weight:700;letter-spacing:0.5px;">' . SITE_NAME . '</span></div>';
    $htmlBody .= '<div style="padding:36px;">';
    $htmlBody .= '<p style="font-size:15px;color:#374151;line-height:1.6;margin:0 0 16px;">Hi there,</p>';
    $htmlBody .= '<p style="font-size:15px;color:#374151;line-height:1.6;margin:0 0 16px;">A <strong>' . $role_label . '</strong> account has been prepared for you on ' . SITE_NAME . '. To get started, please sign in using the details below, then follow the on-screen steps to set up your account.</p>';
    $htmlBody .= '<div style="background:#f0fdf4;border:1px solid #86efac;border-radius:10px;padding:22px 24px;margin:24px 0;">';
    $htmlBody .= '<p style="font-size:14px;color:#065f46;line-height:1.7;margin:0;"><strong>Username:</strong> ' . htmlspecialchars($username) . '</p>';
    $htmlBody .= '<p style="font-size:14px;color:#065f46;line-height:1.7;margin:6px 0 0;"><strong>Password:</strong> ' . htmlspecialchars($password) . '</p>';
    $htmlBody .= '</div>';
    $htmlBody .= '<p style="font-size:13px;color:#6b7280;line-height:1.6;margin:0 0 20px;">For your security, you will be asked to set a new password and choose your security questions when you first sign in. Please do not share these credentials with anyone.</p>';
    $htmlBody .= '<div style="text-align:center;margin:28px 0;"><a href="' . $login_url . '" style="display:inline-block;background:#059669;color:#ffffff;text-decoration:none;font-size:15px;font-weight:600;padding:12px 32px;border-radius:8px;">Sign in to ' . SITE_NAME . '</a></div>';
    $htmlBody .= '<p style="font-size:13px;color:#6b7280;line-height:1.6;margin:24px 0 0;">If you were not expecting an account on ' . SITE_NAME . ', you can safely ignore this email.</p>';
    $htmlBody .= '</div>';
    $htmlBody .= '<div style="background:#f9fafb;padding:18px 36px;text-align:center;border-top:1px solid #e5e7eb;"><p style="font-size:12px;color:#9ca3af;margin:0;">You are receiving this because an account was created for this email address on ' . SITE_NAME . '.</p></div>';
    $htmlBody .= '</div>';

    $textBody = "Hi there,\n\nA $role_label account has been prepared for you on " . SITE_NAME . ".\n\nUsername: $username\nPassword: $password\n\nSign in here: $login_url\n\nFor your security, you will be asked to set a new password and choose your security questions when you first sign in. Please do not share these credentials.\n\nIf you were not expecting an account, you can safely ignore this email.\n\n" . SITE_NAME . " Team";

    $last_error = '';
    for ($attempt = 1; $attempt <= 2; $attempt++) {
        $mail = new PHPMailer(true);
        try {
            $mail->isSMTP();
            $mail->Host       = SMTP_HOST;
            $mail->SMTPAuth   = true;
            $mail->Username   = SMTP_USERNAME;
            $mail->Password   = SMTP_PASSWORD;
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
            $mail->Port       = SMTP_PORT;
            $mail->Timeout    = 30;
            $mail->CharSet    = 'UTF-8';

            $mail->setFrom(SMTP_FROM_EMAIL, SMTP_FROM_NAME);
            $mail->addAddress($email, $username);
            $mail->isHTML(true);
            $mail->Subject = $subject;
            $mail->Body    = $htmlBody;
            $mail->AltBody = $textBody;

            $mail->send();
            return true;
        } catch (Exception $e) {
            $last_error = $mail->ErrorInfo;
            error_log("[Account] PHPMailer error for $email (attempt $attempt): " . $last_error);
            if ($attempt === 1) { usleep(1500000); }
        }
    }
    error_log("[Account] Sending credentials to $email FAILED after retries. Last error: " . $last_error);
    set_last_mail_error($last_error);
    return false;
}

function set_last_mail_error($message) {
    $_SESSION['last_mail_error'] = $message;
}
