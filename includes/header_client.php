<?php
// Client header include — renders the MovieHub navbar (state-aware).
require_once __DIR__ . '/navbar.php';
?>
<script>
    // Prevent right-click on all pages
    document.addEventListener('contextmenu', (e) => {
        e.preventDefault();
        return false;
    });
</script>
