<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/authorization.php';
require_once '../includes/csrf.php';

require_login();
require_role(['admin', 'super_admin']);
require_permission('movies.view');

$success = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token. Please try again.';
    } else {
        $name = trim($_POST['name'] ?? '');
        if (isset($_POST['add_genre'])) {
            if ($name === '' || strlen($name) > 50) { $error = 'Please enter a genre name (max 50 characters).'; }
            else {
                try {
                    $stmt = $pdo->prepare("INSERT INTO genres (name) VALUES (?)");
                    $stmt->execute([$name]);
                    log_audit($pdo, 'genre_added', 'genres', $pdo->lastInsertId(), $name, "Genre '{$name}' added");
                    $success = 'Genre added successfully!';
                } catch (PDOException $e) {
                    $error = ($e->getCode() == 23000) ? 'That genre already exists.' : 'Error adding genre.';
                }
            }
        } elseif (isset($_POST['edit_genre'])) {
            $genre_id = (int)$_POST['genre_id'];
            if ($name === '' || strlen($name) > 50) { $error = 'Please enter a genre name (max 50 characters).'; }
            else {
                try {
                    $stmt = $pdo->prepare("UPDATE genres SET name = ? WHERE id = ?");
                    $stmt->execute([$name, $genre_id]);
                    log_audit($pdo, 'genre_updated', 'genres', $genre_id, $name, "Genre ID {$genre_id} renamed to '{$name}'");
                    $success = 'Genre updated successfully!';
                } catch (PDOException $e) {
                    $error = ($e->getCode() == 23000) ? 'That genre already exists.' : 'Error updating genre.';
                }
            }
        } elseif (isset($_POST['delete_genre'])) {
            $genre_id = (int)$_POST['genre_id'];
            try {
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM movies WHERE genre_id = ?");
                $stmt->execute([$genre_id]);
                if ($stmt->fetchColumn() > 0) {
                    $error = 'Cannot delete a genre that has movies assigned. Reassign those movies first.';
                } else {
                    $stmt = $pdo->prepare("SELECT name FROM genres WHERE id = ?");
                    $stmt->execute([$genre_id]);
                    $gname = $stmt->fetchColumn();
                    $stmt = $pdo->prepare("DELETE FROM genres WHERE id = ?");
                    $stmt->execute([$genre_id]);
                    log_audit($pdo, 'genre_deleted', 'genres', $genre_id, $gname, "Genre '{$gname}' deleted");
                    $success = 'Genre deleted!';
                }
            } catch (PDOException $e) { $error = 'Error deleting genre.'; }
        }
    }
}

try {
    $genres = $pdo->query("SELECT g.id, g.name, COUNT(m.movie_id) AS movie_count FROM genres g LEFT JOIN movies m ON m.genre_id = g.id GROUP BY g.id, g.name ORDER BY g.name")->fetchAll();
} catch (PDOException $e) { $genres = []; }

$pending_requests = 0;
try { $pending_requests = $pdo->query("SELECT COUNT(*) FROM rentals WHERE status = 'pending'")->fetchColumn(); } catch (Exception $e) {}
generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Genres - MovieHub</title>
    <link rel="stylesheet" href="../assets/css/style.css?v=2.3.0">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body>
    <div class="page-wrapper">
        <aside class="sidebar" id="sidebar">
            <div class="sidebar-header"><a href="dashboard.php" class="sidebar-logo"><i class="fas fa-film"></i><span>MovieHub</span></a></div>
            <nav class="sidebar-nav">
<?php require __DIR__ . '/../includes/sidebar_navigation.php'; ?>
</nav>
            <a href="../superadmin/edit_admin.php?id=<?php echo (int)$_SESSION['admin_id']; ?>" class="sidebar-user" style="display:flex;align-items:center;gap:0.75rem;padding:0.75rem 1rem;color:inherit;text-decoration:none;transition:background 0.15s;cursor:pointer;" title="Edit my profile">
                <div class="avatar avatar-sm"><?php echo strtoupper(substr($_SESSION['admin_full_name'], 0, 1)); ?></div>
                <div class="sidebar-user-info">
                    <div class="sidebar-user-name"><?php echo htmlspecialchars($_SESSION['admin_full_name']); ?></div>
                    <div class="sidebar-user-role"><?php echo ucfirst(str_replace('_', ' ', $_SESSION['admin_role'] ?? 'admin')); ?></div>
                </div>
            </a>
        </aside>
        <div class="main-content">
            <div class="top-header">
                <div class="flex items-center gap-3">
                    <button class="sidebar-toggle" onclick="document.getElementById('sidebar').classList.toggle('open');document.getElementById('sidebarOverlay').classList.toggle('active');"><i class="fas fa-bars"></i></button>
                    <div><h1 class="page-title">Manage Genres</h1><p class="page-subtitle">Organize the movie catalog by genre</p></div>
                </div>
                <div class="header-actions"><button class="btn btn-primary" onclick="openAddModal()"><i class="fas fa-plus"></i> Add Genre</button></div>
            </div>
            <div class="content-body">
                <?php if ($success): ?><div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($success); ?></div><?php endif; ?>
                <?php if ($error): ?><div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div><?php endif; ?>
                <div class="card">
                    <div class="table-responsive">
                        <table class="table">
                            <thead><tr><th>#</th><th>Genre</th><th>Movies</th><th>Actions</th></tr></thead>
                            <tbody>
<?php foreach ($genres as $genre): ?>
                                <tr>
                                    <td><strong>#<?php echo (int)$genre['id']; ?></strong></td>
                                    <td><strong><?php echo htmlspecialchars($genre['name']); ?></strong></td>
                                    <td><span class="badge badge-info"><?php echo (int)$genre['movie_count']; ?></span></td>
                                    <td><div class="table-actions">
                                        <button class="btn btn-sm btn-outline" onclick='openEditModal(<?php echo htmlspecialchars(json_encode(['id' => (int)$genre['id'], 'name' => $genre['name']])); ?>)'><i class="fas fa-edit"></i></button>
                                        <button class="btn btn-sm btn-outline-danger" onclick="confirmDelete(<?php echo (int)$genre['id']; ?>,'<?php echo htmlspecialchars($genre['name']); ?>',<?php echo (int)$genre['movie_count']; ?>)"><i class="fas fa-trash"></i></button>
                                    </div></td>
                                </tr>
<?php endforeach; ?>
<?php if (empty($genres)): ?><tr><td colspan="4" class="text-center text-muted" style="padding:2rem;">No genres found.</td></tr><?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div id="addModal" class="modal"><div class="modal-content"><div class="modal-header"><h3 class="modal-title">Add New Genre</h3><span class="close" onclick="closeAddModal()">&times;</span></div><div class="modal-body">
        <form method="POST" action="">
            <?php csrf_token_input(); ?>
            <div class="form-group"><label>Genre Name *</label><input type="text" name="name" class="form-control" maxlength="50" required placeholder="e.g., Action"></div>
            <button type="submit" name="add_genre" class="btn btn-primary" style="width:100%;"><i class="fas fa-plus"></i> Add Genre</button>
        </form>
    </div></div></div>
    <div id="editModal" class="modal"><div class="modal-content"><div class="modal-header"><h3 class="modal-title">Edit Genre</h3><span class="close" onclick="closeEditModal()">&times;</span></div><div class="modal-body">
        <form method="POST" action="">
            <?php csrf_token_input(); ?>
            <input type="hidden" id="edit_genre_id" name="genre_id">
            <div class="form-group"><label>Genre Name *</label><input type="text" id="edit_name" name="name" class="form-control" maxlength="50" required></div>
            <button type="submit" name="edit_genre" class="btn btn-success" style="width:100%;"><i class="fas fa-save"></i> Update Genre</button>
        </form>
    </div></div></div>
    <div id="deleteModal" class="modal"><div class="modal-content"><div class="modal-header"><h3 class="modal-title">Confirm Delete</h3><span class="close" onclick="closeDeleteModal()">&times;</span></div><div class="modal-body">
        <form method="POST" action="">
            <?php csrf_token_input(); ?>
            <input type="hidden" id="delete_genre_id" name="genre_id">
            <p>Are you sure you want to delete the genre "<span id="delete_genre_name"></span>"?</p>
            <p id="delete_genre_warning" class="text-danger font-semibold" style="display:none;">This genre has movies assigned and cannot be deleted.</p>
            <p id="delete_genre_ok" class="text-muted text-sm">This genre is not used by any movie and can be safely deleted.</p>
            <div class="flex gap-3 mt-4">
                <button type="button" class="btn btn-outline" onclick="closeDeleteModal()" style="flex:1;"><i class="fas fa-times"></i> Cancel</button>
                <button type="submit" name="delete_genre" id="delete_genre_btn" class="btn btn-danger" style="flex:1;"><i class="fas fa-trash"></i> Delete</button>
            </div>
        </form>
    </div></div></div>
    <div id="sidebarOverlay" class="sidebar-overlay" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('active');"></div>
    <script>
        function openAddModal() { document.getElementById('addModal').style.display = 'flex'; }
        function closeAddModal() { document.getElementById('addModal').style.display = 'none'; }
        function openEditModal(genre) {
            document.getElementById('edit_genre_id').value = genre.id;
            document.getElementById('edit_name').value = genre.name;
            document.getElementById('editModal').style.display = 'flex';
        }
        function closeEditModal() { document.getElementById('editModal').style.display = 'none'; }
        function confirmDelete(id, name, count) {
            document.getElementById('delete_genre_id').value = id;
            document.getElementById('delete_genre_name').textContent = name;
            var blocked = count > 0;
            document.getElementById('delete_genre_warning').style.display = blocked ? 'block' : 'none';
            document.getElementById('delete_genre_ok').style.display = blocked ? 'none' : 'block';
            document.getElementById('delete_genre_btn').disabled = blocked;
            document.getElementById('deleteModal').style.display = 'flex';
        }
        function closeDeleteModal() { document.getElementById('deleteModal').style.display = 'none'; }
        window.onclick = function(e) { ['addModal','editModal','deleteModal'].forEach(function(id) { if (e.target == document.getElementById(id)) document.getElementById(id).style.display = 'none'; }); };
    </script>
</body>
</html>
