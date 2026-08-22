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

// Load genres for the add/edit selects
$genres = [];
try { $genres = $pdo->query("SELECT id, name FROM genres ORDER BY name")->fetchAll(); } catch (PDOException $e) { $genres = []; }

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token. Please try again.';
    } else {
        $uploadDir = realpath(__DIR__ . '/../assets') . DIRECTORY_SEPARATOR . 'images' . DIRECTORY_SEPARATOR . 'movies';
        if (!is_dir($uploadDir)) { @mkdir($uploadDir, 0777, true); }
        $relUploadDir = '../assets/images/movies/';

        function handle_poster_upload($field, $uploadDir, $relUploadDir) {
            if (!isset($_FILES[$field]) || empty($_FILES[$field]['name'])) { return [null, null]; }
            $file = $_FILES[$field];
            if ($file['error'] !== UPLOAD_ERR_OK) { return [null, 'Poster upload failed.']; }
            if ($file['size'] > MAX_FILE_SIZE) { return [null, 'Poster must be under 5MB.']; }
            $allowed = ['jpg','jpeg','png','gif'];
            $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
            if (!in_array($ext, $allowed, true)) { return [null, 'Invalid image type.']; }
            $info = @getimagesize($file['tmp_name']);
            if ($info === false) { return [null, 'File is not a valid image.']; }
            $basename = 'movie_' . time() . '_' . bin2hex(random_bytes(4)) . '.' . $ext;
            $dest = rtrim($uploadDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $basename;
            if (!move_uploaded_file($file['tmp_name'], $dest)) { return [null, 'Failed to save poster.']; }
            return [$relUploadDir . $basename, null];
        }

        if (isset($_POST['add_movie']) || isset($_POST['edit_movie'])) {
            $title = trim($_POST['title']);
            $genre_id = (int)($_POST['genre_id'] ?? 0);
            $rental_price = (float)$_POST['rental_price'];
            $description = trim($_POST['description']);
            $status = in_array($_POST['status'] ?? '', ['available', 'rented', 'maintenance'], true) ? $_POST['status'] : 'available';
            $release_year = (isset($_POST['release_year']) && $_POST['release_year'] !== '') ? (int)$_POST['release_year'] : null;
            $director = trim($_POST['director'] ?? '');
            $cast_members = trim($_POST['cast_members'] ?? '');
            $duration_minutes = (isset($_POST['duration_minutes']) && $_POST['duration_minutes'] !== '') ? (int)$_POST['duration_minutes'] : null;
            $rating = (isset($_POST['rating']) && $_POST['rating'] !== '') ? round((float)$_POST['rating'], 1) : null;
            list($posterPath, $imgErr) = handle_poster_upload('poster', $uploadDir, $relUploadDir);

            if (empty($title) || $genre_id <= 0 || $rental_price <= 0) { $error = 'Please fill in all required fields.'; }
            elseif ($release_year !== null && ($release_year < 1900 || $release_year > (int)date('Y') + 5)) { $error = 'Please enter a valid release year.'; }
            elseif ($duration_minutes !== null && ($duration_minutes < 1 || $duration_minutes > 1000)) { $error = 'Please enter a valid duration in minutes.'; }
            elseif ($rating !== null && ($rating < 0 || $rating > 10)) { $error = 'Rating must be between 0 and 10.'; }
            elseif ($imgErr) { $error = $imgErr; }
            else {
                try {
                    if (isset($_POST['add_movie'])) {
                        $stmt = $pdo->prepare("INSERT INTO movies (title, description, genre_id, release_year, director, cast_members, duration_minutes, rating, rental_price, poster, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
                        $stmt->execute([$title, $description, $genre_id, $release_year, $director, $cast_members, $duration_minutes, $rating, $rental_price, $posterPath, $status]);
                        $success = 'Movie added successfully!';
                    } else {
                        $movie_id = (int)$_POST['movie_id'];
                        if ($posterPath) {
                            $stmt = $pdo->prepare("UPDATE movies SET title=?, description=?, genre_id=?, release_year=?, director=?, cast_members=?, duration_minutes=?, rating=?, rental_price=?, status=?, poster=? WHERE movie_id=?");
                            $stmt->execute([$title, $description, $genre_id, $release_year, $director, $cast_members, $duration_minutes, $rating, $rental_price, $status, $posterPath, $movie_id]);
                        } else {
                            $stmt = $pdo->prepare("UPDATE movies SET title=?, description=?, genre_id=?, release_year=?, director=?, cast_members=?, duration_minutes=?, rating=?, rental_price=?, status=? WHERE movie_id=?");
                            $stmt->execute([$title, $description, $genre_id, $release_year, $director, $cast_members, $duration_minutes, $rating, $rental_price, $status, $movie_id]);
                        }
                        $success = 'Movie updated successfully!';
                    }
                } catch (PDOException $e) { $error = isset($_POST['add_movie']) ? 'Error adding movie.' : 'Error updating movie.'; }
            }
        } elseif (isset($_POST['delete_movie'])) {
            $movie_id = (int)$_POST['movie_id'];
            try {
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM rentals WHERE movie_id = ? AND status = 'pending'");
                $stmt->execute([$movie_id]);
                if ($stmt->fetchColumn() > 0) { $error = 'Cannot delete movie with pending rentals.'; }
                else { $stmt = $pdo->prepare("DELETE FROM movies WHERE movie_id = ?"); $stmt->execute([$movie_id]); $success = 'Movie deleted!'; }
            } catch (PDOException $e) { $error = 'Error deleting movie.'; }
        }
    }
}

try { $movies = $pdo->query("SELECT m.*, g.name AS genre FROM movies m LEFT JOIN genres g ON m.genre_id = g.id ORDER BY m.title")->fetchAll(); } catch (PDOException $e) { $movies = []; }
$pending_requests = 0;
try { $pending_requests = $pdo->query("SELECT COUNT(*) FROM rentals WHERE status = 'pending'")->fetchColumn(); } catch(Exception $e) {}
generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Movies - MovieHub</title>
    <link rel="stylesheet" href="../assets/css/style.css?v=2.3.0">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body>
    <div class="page-wrapper">
        <aside class="sidebar" id="sidebar">
            <div class="sidebar-header"><a href="dashboard.php" class="sidebar-logo"><i class="fas fa-film"></i><span>MovieHub</span></a></div>
            <nav class="sidebar-nav">
                <div class="sidebar-section"><div class="sidebar-section-title">Main</div>
                    <a href="dashboard.php" class="sidebar-link"><i class="fas fa-tachometer-alt"></i><span>Dashboard</span></a>
                </div>
                <div class="sidebar-section"><div class="sidebar-section-title">Management</div>
                    <a href="account_management.php" class="sidebar-link"><i class="fas fa-users-cog"></i><span>Account Management</span></a>
                    <a href="manage_movies.php" class="sidebar-link active"><i class="fas fa-film"></i><span>Manage Movies</span></a>
                    <a href="manage_genres.php" class="sidebar-link"><i class="fas fa-tags"></i><span>Manage Genres</span></a>
                    <a href="rental_requests.php" class="sidebar-link"><i class="fas fa-clipboard-list"></i><span>Rental Requests</span>
                        <?php if ($pending_requests > 0): ?><span class="badge badge-warning"><?php echo $pending_requests; ?></span><?php endif; ?>
                    </a>
                    <a href="registration_approval.php" class="sidebar-link"><i class="fas fa-user-check"></i><span>Approvals</span></a>
                    <a href="login_logs.php" class="sidebar-link"><i class="fas fa-history"></i><span>Login Logs</span></a>
                </div>
                <div class="sidebar-section"><div class="sidebar-section-title">Account</div>
                    <a href="logout.php" class="sidebar-link"><i class="fas fa-sign-out-alt"></i><span>Logout</span></a>
                </div>
            </nav>
            <div class="sidebar-user">
                <div class="avatar avatar-sm"><?php echo strtoupper(substr($_SESSION['admin_full_name'], 0, 1)); ?></div>
                <div class="sidebar-user-info">
                    <div class="sidebar-user-name"><?php echo htmlspecialchars($_SESSION['admin_full_name']); ?></div>
                    <div class="sidebar-user-role"><?php echo ucfirst(str_replace('_', ' ', $_SESSION['admin_role'] ?? 'admin')); ?></div>
                </div>
            </div>
        </aside>
        <div class="main-content">
            <div class="top-header">
                <div class="flex items-center gap-3">
                    <button class="sidebar-toggle" onclick="document.getElementById('sidebar').classList.toggle('open');document.getElementById('sidebarOverlay').classList.toggle('active');"><i class="fas fa-bars"></i></button>
                    <div><h1 class="page-title">Manage Movies</h1><p class="page-subtitle">Add, edit, or remove movies from the catalog</p></div>
                </div>
                <div class="header-actions"><button class="btn btn-primary" onclick="openAddModal()"><i class="fas fa-plus"></i> Add Movie</button></div>
            </div>
            <div class="content-body">
                <?php if ($success): ?><div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($success); ?></div><?php endif; ?>
                <?php if ($error): ?><div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div><?php endif; ?>
                <div class="card">
                    <div class="table-responsive">
                        <table class="table">
                            <thead><tr><th>Poster</th><th>Title</th><th>Genre</th><th>Year</th><th>Duration</th><th>Price</th><th>Status</th><th>Actions</th></tr></thead>
                            <tbody>
<?php foreach ($movies as $movie): ?>
                                <tr>
                                    <td><?php if (!empty($movie['poster'])): ?><img src="<?php echo htmlspecialchars($movie['poster']); ?>" style="width:50px;height:50px;object-fit:cover;border-radius:var(--radius);"><?php else: ?><div style="width:50px;height:50px;background:var(--background);border-radius:var(--radius);display:flex;align-items:center;justify-content:center;"><i class="fas fa-film" style="color:var(--muted);"></i></div><?php endif; ?></td>
                                    <td><strong><?php echo htmlspecialchars($movie['title']); ?></strong><br><small class="text-muted"><?php echo $movie['rating'] !== null ? '<i class="fas fa-star" style="color:#f59e0b;"></i> ' . number_format((float)$movie['rating'], 1) . ' / 10' : ''; ?></small></td>
                                    <td><?php echo htmlspecialchars($movie['genre'] ?? ''); ?></td>
                                    <td><?php echo $movie['release_year'] ? (int)$movie['release_year'] : '—'; ?></td>
                                    <td><?php echo $movie['duration_minutes'] ? (int)$movie['duration_minutes'] . ' min' : '—'; ?></td>
                                    <td><?php echo CURRENCY_SYMBOL.number_format($movie['rental_price'],2); ?></td>
                                    <td><span class="status-badge status-<?php echo $movie['status']; ?>"><?php echo ucfirst($movie['status']); ?></span></td>
                                    <td><div class="table-actions">
                                        <button class="btn btn-sm btn-outline" onclick='openEditModal(<?php echo htmlspecialchars(json_encode($movie)); ?>)'><i class="fas fa-edit"></i></button>
                                        <button class="btn btn-sm btn-outline-danger" onclick="confirmDelete(<?php echo $movie['movie_id']; ?>,'<?php echo htmlspecialchars($movie['title']); ?>')"><i class="fas fa-trash"></i></button>
                                    </div></td>
                                </tr>
<?php endforeach; ?>
<?php if (empty($movies)): ?><tr><td colspan="8" class="text-center text-muted" style="padding:2rem;">No movies found.</td></tr><?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div id="addModal" class="modal"><div class="modal-content"><div class="modal-header"><h3 class="modal-title">Add New Movie</h3><span class="close" onclick="closeAddModal()">&times;</span></div><div class="modal-body">
        <form method="POST" action="" enctype="multipart/form-data">
            <?php csrf_token_input(); ?>
            <div class="form-group"><label>Title *</label><input type="text" name="title" class="form-control" required></div>
            <div class="form-group"><label>Genre *</label><select name="genre_id" class="form-control" required><option value="">Select Genre</option><?php foreach ($genres as $g): ?><option value="<?php echo (int)$g['id']; ?>"><?php echo htmlspecialchars($g['name']); ?></option><?php endforeach; ?></select></div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.75rem;">
                <div class="form-group"><label>Release Year</label><input type="number" name="release_year" class="form-control" min="1900" max="<?php echo (int)date('Y') + 5; ?>" placeholder="e.g., 2024"></div>
                <div class="form-group"><label>Duration (minutes)</label><input type="number" name="duration_minutes" class="form-control" min="1" max="1000" placeholder="e.g., 128"></div>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.75rem;">
                <div class="form-group"><label>Director</label><input type="text" name="director" class="form-control" maxlength="100" placeholder="e.g., Christopher Nolan"></div>
                <div class="form-group"><label>Rating (0-10)</label><input type="number" name="rating" class="form-control" step="0.1" min="0" max="10" placeholder="e.g., 8.5"></div>
            </div>
            <div class="form-group"><label>Cast</label><textarea name="cast_members" class="form-control" rows="2" placeholder="Comma-separated cast members"></textarea></div>
            <div class="form-group"><label>Rental Price *</label><input type="number" name="rental_price" class="form-control" step="0.01" min="0" required></div>
            <div class="form-group"><label>Status</label><select name="status" class="form-control"><option value="available">Available</option><option value="rented">Rented</option><option value="maintenance">Maintenance</option></select></div>
            <div class="form-group"><label>Description</label><textarea name="description" class="form-control" rows="3"></textarea></div>
            <div class="form-group"><label>Poster</label><input type="file" name="poster" class="form-control" accept="image/*"></div>
            <button type="submit" name="add_movie" class="btn btn-primary" style="width:100%;"><i class="fas fa-plus"></i> Add Movie</button>
        </form>
    </div></div></div>
    <div id="editModal" class="modal"><div class="modal-content" style="max-height:85vh;overflow-y:auto;"><div class="modal-header"><h3 class="modal-title">Edit Movie</h3><span class="close" onclick="closeEditModal()">&times;</span></div><div class="modal-body">
        <form method="POST" action="" enctype="multipart/form-data">
            <?php csrf_token_input(); ?>
            <input type="hidden" id="edit_movie_id" name="movie_id">
            <div class="form-group"><label>Title *</label><input type="text" id="edit_title" name="title" class="form-control" required></div>
            <div class="form-group"><label>Genre *</label><select id="edit_genre_id" name="genre_id" class="form-control" required><option value="">Select Genre</option><?php foreach ($genres as $g): ?><option value="<?php echo (int)$g['id']; ?>"><?php echo htmlspecialchars($g['name']); ?></option><?php endforeach; ?></select></div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.75rem;">
                <div class="form-group"><label>Release Year</label><input type="number" id="edit_release_year" name="release_year" class="form-control" min="1900" max="<?php echo (int)date('Y') + 5; ?>"></div>
                <div class="form-group"><label>Duration (minutes)</label><input type="number" id="edit_duration_minutes" name="duration_minutes" class="form-control" min="1" max="1000"></div>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.75rem;">
                <div class="form-group"><label>Director</label><input type="text" id="edit_director" name="director" class="form-control" maxlength="100"></div>
                <div class="form-group"><label>Rating (0-10)</label><input type="number" id="edit_rating" name="rating" class="form-control" step="0.1" min="0" max="10"></div>
            </div>
            <div class="form-group"><label>Cast</label><textarea id="edit_cast_members" name="cast_members" class="form-control" rows="2" placeholder="Comma-separated cast members"></textarea></div>
            <div class="form-group"><label>Rental Price *</label><input type="number" id="edit_rental_price" name="rental_price" class="form-control" step="0.01" min="0" required></div>
            <div class="form-group"><label>Status</label><select id="edit_status" name="status" class="form-control"><option value="available">Available</option><option value="rented">Rented</option><option value="maintenance">Maintenance</option></select></div>
            <div class="form-group"><label>Description</label><textarea id="edit_description" name="description" class="form-control" rows="3"></textarea></div>
            <div class="form-group"><label>Poster (optional)</label><div class="flex items-center gap-3"><img id="edit_poster_preview" style="width:80px;height:80px;object-fit:cover;border-radius:var(--radius);background:var(--background);"><input type="file" id="edit_poster" name="poster" class="form-control" accept="image/*"></div></div>
            <button type="submit" name="edit_movie" class="btn btn-success" style="width:100%;"><i class="fas fa-save"></i> Update Movie</button>
        </form>
    </div></div></div>
    <div id="deleteModal" class="modal"><div class="modal-content"><div class="modal-header"><h3 class="modal-title">Confirm Delete</h3><span class="close" onclick="closeDeleteModal()">&times;</span></div><div class="modal-body">
        <form method="POST" action="">
            <?php csrf_token_input(); ?>
            <input type="hidden" id="delete_movie_id" name="movie_id">
            <p>Are you sure you want to delete "<span id="delete_movie_name"></span>"?</p>
            <p class="text-danger font-semibold">This action cannot be undone!</p>
            <div class="flex gap-3 mt-4">
                <button type="button" class="btn btn-outline" onclick="closeDeleteModal()" style="flex:1;"><i class="fas fa-times"></i> Cancel</button>
                <button type="submit" name="delete_movie" class="btn btn-danger" style="flex:1;"><i class="fas fa-trash"></i> Delete</button>
            </div>
        </form>
    </div></div></div>
    <div id="sidebarOverlay" class="sidebar-overlay" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('active');"></div>
    <script>
        function openAddModal() { document.getElementById('addModal').style.display = 'flex'; }
        function closeAddModal() { document.getElementById('addModal').style.display = 'none'; }
        function openEditModal(movie) {
            document.getElementById('edit_movie_id').value = movie.movie_id;
            document.getElementById('edit_title').value = movie.title;
            document.getElementById('edit_genre_id').value = movie.genre_id || '';
            document.getElementById('edit_release_year').value = movie.release_year || '';
            document.getElementById('edit_duration_minutes').value = movie.duration_minutes || '';
            document.getElementById('edit_director').value = movie.director || '';
            document.getElementById('edit_rating').value = movie.rating !== null && movie.rating !== undefined ? movie.rating : '';
            document.getElementById('edit_cast_members').value = movie.cast_members || '';
            document.getElementById('edit_rental_price').value = movie.rental_price;
            document.getElementById('edit_status').value = movie.status;
            document.getElementById('edit_description').value = movie.description || '';
            var prev = document.getElementById('edit_poster_preview');
            if (prev) prev.src = movie.poster || '';
            document.getElementById('editModal').style.display = 'flex';
        }
        function closeEditModal() { document.getElementById('editModal').style.display = 'none'; }
        function confirmDelete(id, name) { document.getElementById('delete_movie_id').value = id; document.getElementById('delete_movie_name').textContent = name; document.getElementById('deleteModal').style.display = 'flex'; }
        function closeDeleteModal() { document.getElementById('deleteModal').style.display = 'none'; }
        window.onclick = function(e) { ['addModal','editModal','deleteModal'].forEach(function(id) { if (e.target == document.getElementById(id)) document.getElementById(id).style.display = 'none'; }); };
        (function(){ var f=document.getElementById('edit_poster'),p=document.getElementById('edit_poster_preview'); if(f) f.addEventListener('change',function(){ var file=f.files&&f.files[0]; if(file&&p) p.src=URL.createObjectURL(file); }); })();
    </script>
</body>
</html>
