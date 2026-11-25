<?php
$sidebar_role = $_SESSION['admin_role'] ?? '';
$sidebar_is_superadmin = $sidebar_role === 'super_admin';
$sidebar_in_superadmin = strpos($_SERVER['SCRIPT_NAME'] ?? '', '/superadmin/') !== false;
$sidebar_page = basename($_SERVER['SCRIPT_NAME'] ?? '');
$sidebar_admin_base = $sidebar_in_superadmin ? '../admin/' : '';
$sidebar_super_base = $sidebar_in_superadmin ? '' : '../superadmin/';

$sidebar_link = static function ($href, $label, $icon) use ($sidebar_page) {
    $target = basename(parse_url($href, PHP_URL_PATH) ?: '');
    $active = $target !== '' && $target === $sidebar_page ? ' active' : '';
    return '<a href="' . htmlspecialchars($href, ENT_QUOTES, 'UTF-8') . '" class="sidebar-link' . $active . '"><i class="fas ' . htmlspecialchars($icon, ENT_QUOTES, 'UTF-8') . '"></i><span>' . htmlspecialchars($label, ENT_QUOTES, 'UTF-8') . '</span></a>';
};
?>
<nav class="sidebar-nav">
<?php if ($sidebar_is_superadmin): ?>
    <div class="sidebar-section"><div class="sidebar-section-title">Overview</div>
        <?php echo $sidebar_link($sidebar_super_base . 'dashboard.php', 'Dashboard', 'fa-tachometer-alt'); ?>
    </div>
    <div class="sidebar-section"><div class="sidebar-section-title">User Management</div>
        <?php echo $sidebar_link($sidebar_super_base . 'account_management.php', 'Account Management', 'fa-users-cog'); ?>
        <?php echo $sidebar_link($sidebar_super_base . 'create_account.php', 'Create Account', 'fa-user-plus'); ?>
        <?php echo $sidebar_link($sidebar_admin_base . 'registration_approval.php', 'Registration Approvals', 'fa-user-check'); ?>
        <?php echo $sidebar_link($sidebar_super_base . 'privilege_management.php', 'Privileges', 'fa-shield-alt'); ?>
        <?php echo $sidebar_link($sidebar_super_base . 'block_requests.php', 'Block Requests', 'fa-ban'); ?>
        <?php echo $sidebar_link($sidebar_super_base . 'deletion_requests.php', 'Deletion Requests', 'fa-user-minus'); ?>
    </div>
    <div class="sidebar-section"><div class="sidebar-section-title">Catalog</div>
        <?php echo $sidebar_link($sidebar_super_base . 'manage_movies.php', 'Movie Management', 'fa-film'); ?>
        <?php echo $sidebar_link($sidebar_super_base . 'movie_deletion_requests.php', 'Movie Deletion Requests', 'fa-file-import'); ?>
    </div>
    <div class="sidebar-section"><div class="sidebar-section-title">Activity</div>
        <?php echo $sidebar_link($sidebar_admin_base . 'login_logs.php', 'Login Logs', 'fa-history'); ?>
    </div>
<?php else: ?>
    <div class="sidebar-section"><div class="sidebar-section-title">Main</div>
        <?php echo $sidebar_link($sidebar_admin_base . 'dashboard.php', 'Dashboard', 'fa-tachometer-alt'); ?>
    </div>
    <div class="sidebar-section"><div class="sidebar-section-title">Management</div>
        <?php echo $sidebar_link($sidebar_admin_base . 'account_management.php', 'Account Management', 'fa-users-cog'); ?>
        <?php echo $sidebar_link($sidebar_in_superadmin ? 'privilege_management.php' : '../superadmin/privilege_management.php', 'Privileges', 'fa-shield-alt'); ?>
        <?php echo $sidebar_link($sidebar_admin_base . 'manage_movies.php', 'Manage Movies', 'fa-film'); ?>
        <?php echo $sidebar_link($sidebar_admin_base . 'manage_genres.php', 'Manage Genres', 'fa-tags'); ?>
        <?php echo $sidebar_link($sidebar_admin_base . 'rental_requests.php', 'Rental Requests', 'fa-clipboard-list'); ?>
        <?php echo $sidebar_link($sidebar_admin_base . 'registration_approval.php', 'Approvals', 'fa-user-check'); ?>
    </div>
    <div class="sidebar-section"><div class="sidebar-section-title">Activity</div>
        <?php echo $sidebar_link($sidebar_admin_base . 'login_logs.php', 'Login Logs', 'fa-history'); ?>
    </div>
<?php endif; ?>
</nav>
