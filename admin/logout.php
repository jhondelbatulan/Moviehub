<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';
require_once '../includes/csrf.php';

$auth = new Auth($pdo);
$auth->logout();

header('Location: ../client/login.php');
exit();
