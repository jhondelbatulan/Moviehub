<?php
// MovieHub top navbar — adapts to guest / customer / admin sessions.
// Expects config.php to be loaded (session started by caller pages).

$currentScript = $_SERVER['SCRIPT_NAME'] ?? '';
$inClient = strpos($currentScript, '/client/') !== false;
$inAdmin = strpos($currentScript, '/admin/') !== false;
$inSuper = strpos($currentScript, '/superadmin/') !== false;
$basePath = ($inClient || $inAdmin || $inSuper) ? '../' : '';

$isAdminSession = isset($_SESSION['admin_id']) || isset($_SESSION['super_admin_id']);
$isUserSession = !$isAdminSession && isset($_SESSION['user_id']);
$isClientDashboard = $isUserSession && basename($currentScript) === 'dashboard.php';

// Active-link detection
$uri = $_SERVER['REQUEST_URI'] ?? '';
$mhActive = function ($needle) use ($uri) {
    return strpos($uri, $needle) !== false ? 'active' : '';
};

if ($isAdminSession):
    $adminName = $_SESSION['admin_full_name'] ?? $_SESSION['full_name'] ?? 'Admin';
    $adminDash = $inAdmin ? 'dashboard.php' : ($inSuper ? 'dashboard.php' : ($basePath . 'admin/dashboard.php'));
    $logoutUrl = $basePath . 'client/logout.php';
?>
<nav class="mh-navbar">
    <a href="<?php echo $basePath; ?>index.php" class="mh-brand"><i class="fas fa-film"></i>MovieHub</a>
    <ul class="mh-nav-links" id="mhNavLinks">
        <li><a href="<?php echo $basePath; ?>index.php" class="<?php echo $mhActive('/index.php'); ?>">Home</a></li>
        <li><a href="<?php echo $basePath; ?>admin/dashboard.php" class="<?php echo $mhActive('/admin/dashboard.php'); ?>">Admin Dashboard</a></li>
        <li><a href="<?php echo $basePath; ?>admin/manage_movies.php" class="<?php echo $mhActive('/admin/manage_movies.php'); ?>">Movies</a></li>
        <li><a href="<?php echo $basePath; ?>admin/manage_genres.php" class="<?php echo $mhActive('/admin/manage_genres.php'); ?>">Genres</a></li>
        <li><a href="<?php echo $basePath; ?>admin/rental_requests.php" class="<?php echo $mhActive('/admin/rental_requests.php'); ?>">Rentals</a></li>
    </ul>
    <div class="mh-nav-right">
        <span class="mh-user-chip"><span class="avatar avatar-sm"><?php echo strtoupper(substr($adminName, 0, 1)); ?></span><span><?php echo htmlspecialchars($adminName); ?></span></span>
        <a href="<?php echo $basePath; ?>admin/logout.php" class="btn btn-sm btn-outline"><i class="fas fa-sign-out-alt"></i> Logout</a>
        <button class="mh-burger" onclick="document.getElementById('mhNavLinks').classList.toggle('open')" aria-label="Menu"><i class="fas fa-bars"></i></button>
    </div>
</nav>
<?php elseif ($isUserSession):
    $userName = $_SESSION['full_name'] ?? 'My Account';
    $initial = strtoupper(substr($userName, 0, 1));
    $profilePic = $_SESSION['profile_picture'] ?? '';
?>
<nav class="mh-navbar">
    <a href="<?php echo $basePath; ?>index.php" class="mh-brand"><i class="fas fa-film"></i>MovieHub</a>
    <ul class="mh-nav-links" id="mhNavLinks">
        <li><a href="<?php echo $basePath; ?>index.php" class="<?php echo $mhActive('/index.php'); ?>">Home</a></li>
        <li><a href="<?php echo $basePath; ?>client/movies.php" class="<?php echo $mhActive('/client/movies.php') ?: $mhActive('/client/movie_details.php'); ?>">Movies</a></li>
        <li><a href="<?php echo $basePath; ?>client/movies.php#genres-filter">Genres</a></li>
        <li><a href="<?php echo $basePath; ?>client/dashboard.php#my-rentals" class="<?php echo $mhActive('/client/dashboard.php'); ?>">My Rentals</a></li>
        <li><a href="<?php echo $basePath; ?>client/logs.php" class="<?php echo $mhActive('/client/logs.php'); ?>">My Activity</a></li>
        <li><a href="<?php echo $basePath; ?>client/profile.php" class="<?php echo $mhActive('/client/profile.php'); ?>">Account</a></li>
    </ul>
    <div class="mh-nav-right">
        <a href="<?php echo $basePath; ?>client/profile.php" class="mh-user-chip">
            <?php if (!empty($profilePic)): ?>
                <img src="<?php echo htmlspecialchars($profilePic); ?>" style="width:28px;height:28px;border-radius:50%;object-fit:cover;" alt="">
            <?php else: ?>
                <span class="avatar avatar-sm"><?php echo htmlspecialchars($initial); ?></span>
            <?php endif; ?>
            <span><?php echo htmlspecialchars($userName); ?></span>
        </a>
        <?php if (!$isClientDashboard): ?><a href="<?php echo $basePath; ?>client/logout.php" class="btn btn-sm btn-outline"><i class="fas fa-sign-out-alt"></i> Logout</a><?php endif; ?>
        <button class="mh-burger" onclick="document.getElementById('mhNavLinks').classList.toggle('open')" aria-label="Menu"><i class="fas fa-bars"></i></button>
    </div>
</nav>
<?php else: ?>
<nav class="mh-navbar">
    <a href="<?php echo $basePath; ?>index.php" class="mh-brand"><i class="fas fa-film"></i>MovieHub</a>
    <ul class="mh-nav-links" id="mhNavLinks">
        <li><a href="<?php echo $basePath; ?>index.php" class="<?php echo $mhActive('/index.php'); ?>">Home</a></li>
        <li><a href="<?php echo $basePath; ?>client/login.php">Movies</a></li>
        <li><a href="<?php echo $basePath; ?>client/login.php">Genres</a></li>
        <li><a href="<?php echo $basePath; ?>client/login.php">My Rentals</a></li>
    </ul>
    <div class="mh-nav-right">
        <a href="<?php echo $basePath; ?>client/login.php" class="btn btn-sm btn-outline"><i class="fas fa-sign-in-alt"></i> Login</a>
        <a href="<?php echo $basePath; ?>client/register.php" class="btn btn-sm btn-primary"><i class="fas fa-user-plus"></i> Register</a>
        <button class="mh-burger" onclick="document.getElementById('mhNavLinks').classList.toggle('open')" aria-label="Menu"><i class="fas fa-bars"></i></button>
    </div>
</nav>
<?php endif; ?>
