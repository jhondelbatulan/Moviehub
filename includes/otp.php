<?php
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/functions.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

function send_otp_email($email, $otp, $full_name = '') {
    if (!EMAIL_ENABLED) {
        error_log("[OTP] Email disabled. OTP for $email: $otp");
        return true;
    }

    $name = $full_name ?: 'User';
    $subject = SITE_NAME . ' - Your One-Time Password';

    $htmlBody  = '<div style="font-family:Inter,Arial,sans-serif;max-width:480px;margin:auto;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden;">';
    $htmlBody .= '<div style="background:#059669;padding:24px 32px;text-align:center;"><h1 style="color:#fff;margin:0;font-size:22px;">' . SITE_NAME . '</h1></div>';
    $htmlBody .= '<div style="padding:32px;">';
    $htmlBody .= '<p style="font-size:15px;color:#374151;">Hello <strong>' . htmlspecialchars($name) . '</strong>,</p>';
    $htmlBody .= '<p style="font-size:15px;color:#374151;">You requested a One-Time Password (OTP) for password reset. Use the code below:</p>';
    $htmlBody .= '<div style="background:#f9fafb;border:1px dashed #059669;border-radius:8px;padding:20px;text-align:center;margin:24px 0;">';
    $htmlBody .= '<span style="font-size:32px;font-weight:700;letter-spacing:8px;color:#059669;font-family:monospace;">' . $otp . '</span>';
    $htmlBody .= '</div>';
    $htmlBody .= '<p style="font-size:13px;color:#6b7280;">This code will expire in <strong>' . OTP_EXPIRY_MINUTES . ' minutes</strong>.</p>';
    $htmlBody .= '<p style="font-size:13px;color:#6b7280;">If you did not request this, please ignore this email.</p>';
    $htmlBody .= '</div>';
    $htmlBody .= '<div style="background:#f9fafb;padding:16px 32px;text-align:center;border-top:1px solid #e5e7eb;"><p style="font-size:12px;color:#9ca3af;margin:0;">&copy; ' . date('Y') . ' ' . SITE_NAME . ' &mdash; All rights reserved.</p></div>';
    $htmlBody .= '</div>';

    $textBody = "Hello $name,\n\nYour One-Time Password (OTP) is:\n\n$otp\n\nThis code expires in " . OTP_EXPIRY_MINUTES . " minutes.\nIf you did not request this, ignore this email.\n\n" . SITE_NAME . " Team";

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
