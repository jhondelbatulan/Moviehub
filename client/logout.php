<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';

$auth = new Auth($pdo);
$auth->logout();

header('Location: login.php');
exit();
