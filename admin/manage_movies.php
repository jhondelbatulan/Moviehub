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
$is_super = (($_SESSION['admin_role'] ?? '') === 'super_admin');

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

        // Validate + store a supporting change document (PDF/JPG/PNG/WEBP, max 5MB).
        function handle_change_document_upload($field) {
            if (!isset($_FILES[$field]) || empty($_FILES[$field]['name'])) { return [null, null, null, 'A supporting document is required before performing this action.']; }
            $file = $_FILES[$field];
            if ($file['error'] !== UPLOAD_ERR_OK || !is_uploaded_file($file['tmp_name'])) { return [null, null, null, 'Document upload failed.']; }
            $allowed_mimes = ['application/pdf', 'image/jpeg', 'image/png', 'image/webp'];
            $allowed_exts = ['pdf', 'jpg', 'jpeg', 'png', 'webp'];
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $mime = finfo_file($finfo, $file['tmp_name']);
            finfo_close($finfo);
            $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
            if (!in_array($mime, $allowed_mimes, true) || !in_array($ext, $allowed_exts, true)) { return [null, null, null, 'Invalid document type. Allowed: PDF, JPG, PNG, WEBP.']; }
            if ($file['size'] > (5 * 1024 * 1024)) { return [null, null, null, 'Document must not exceed 5MB.']; }
            $upload_dir = __DIR__ . '/../assets/movie_change_documents/';
            if (!is_dir($upload_dir)) { @mkdir($upload_dir, 0777, true); }
            $safe_name = preg_replace('/[^A-Za-z0-9._-]/', '_', $file['name']);
            $stored_name = 'movie_' . time() . '_' . uniqid() . '.' . $ext;
            $dest = $upload_dir . $stored_name;
            if (!move_uploaded_file($file['tmp_name'], $dest)) { return [null, null, null, 'Failed to upload document. Please try again.']; }
            return [$stored_name, $safe_name, $mime, null];
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

            $change_reason = trim($_POST['change_reason'] ?? '');
            $change_password = $_POST['change_admin_password'] ?? '';

            if (empty($title) || $genre_id <= 0 || $rental_price <= 0) { $error = 'Please fill in all required fields.'; }
            elseif ($release_year !== null && ($release_year < 1900 || $release_year > (int)date('Y') + 5)) { $error = 'Please enter a valid release year.'; }
            elseif ($duration_minutes !== null && ($duration_minutes < 1 || $duration_minutes > 1000)) { $error = 'Please enter a valid duration in minutes.'; }
            elseif ($rating !== null && ($rating < 0 || $rating > 10)) { $error = 'Rating must be between 0 and 10.'; }
            elseif ($imgErr) { $error = $imgErr; }
            // Admins (non-super) must justify every movie edit: reason + supporting document + password confirmation.
            elseif (isset($_POST['edit_movie']) && !$is_super && $change_reason === '') { $error = 'A reason is required before editing a movie.'; }
            elseif (isset($_POST['edit_movie']) && !$is_super && $change_password === '') { $error = 'Please enter your current password to confirm this action.'; }
            elseif (isset($_POST['edit_movie']) && !$is_super && !check_user_password($pdo, 'admin_users', $_SESSION['admin_id'], $change_password)) { $error = 'Inputted password is wrong.'; }
            else {
                // The document is only required for admin edits (not super admin, not adds).
                $docStored = null; $docSafe = null; $docMime = null; $docErr = null;
                if (isset($_POST['edit_movie']) && !$is_super) {
                    list($docStored, $docSafe, $docMime, $docErr) = handle_change_document_upload('change_document');
                }
                if ($docErr) {
                    $error = $docErr;
                } else {
                    try {
                        if (isset($_POST['add_movie'])) {
                            $stmt = $pdo->prepare("INSERT INTO movies (title, description, genre_id, release_year, director, cast_members, duration_minutes, rating, rental_price, poster, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
                            $stmt->execute([$title, $description, $genre_id, $release_year, $director, $cast_members, $duration_minutes, $rating, $rental_price, $posterPath, $status]);
                            log_audit($pdo, 'movie_added', 'movies', (int)$pdo->lastInsertId(), $title, 'Movie "' . $title . '" added by ' . ($_SESSION['admin_full_name'] ?? 'admin'));
                            $success = 'Movie added successfully!';
                        } else {
                            $movie_id = (int)$_POST['movie_id'];
                            $stmt = $pdo->prepare("SELECT title FROM movies WHERE movie_id = ?");
                            $stmt->execute([$movie_id]);
                            $existing = $stmt->fetch();
                            if (!$existing) {
                                $error = 'Movie not found.';
                            } else {
                                if ($posterPath) {
                                    $stmt = $pdo->prepare("UPDATE movies SET title=?, description=?, genre_id=?, release_year=?, director=?, cast_members=?, duration_minutes=?, rating=?, rental_price=?, status=?, poster=? WHERE movie_id=?");
                                    $stmt->execute([$title, $description, $genre_id, $release_year, $director, $cast_members, $duration_minutes, $rating, $rental_price, $status, $posterPath, $movie_id]);
                                } else {
                                    $stmt = $pdo->prepare("UPDATE movies SET title=?, description=?, genre_id=?, release_year=?, director=?, cast_members=?, duration_minutes=?, rating=?, rental_price=?, status=? WHERE movie_id=?");
                                    $stmt->execute([$title, $description, $genre_id, $release_year, $director, $cast_members, $duration_minutes, $rating, $rental_price, $status, $movie_id]);
                                }
                                if ($is_super) {
                                    log_audit($pdo, 'movie_updated', 'movies', $movie_id, $title, 'Movie "' . $title . '" (ID: ' . $movie_id . ') updated by Super Admin');
                                } else {
                                    // Keep the admin's justification on record.
                                    $stmt = $pdo->prepare("INSERT INTO movie_edit_logs (movie_id, movie_title, reason, file_path, original_name, file_size, mime_type, edited_by_id, edited_by_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
                                    $stmt->execute([$movie_id, $title, $change_reason, $docStored, $docSafe, (int)($_FILES['change_document']['size'] ?? 0), $docMime, $_SESSION['admin_id'], $_SESSION['admin_full_name'] ?? '']);
                                    log_audit($pdo, 'movie_updated', 'movies', $movie_id, $title, 'Movie "' . $title . '" (ID: ' . $movie_id . ') edited by Admin: ' . $change_reason);
                                }
                                $success = 'Movie updated successfully!';
                            }
                        }
                    } catch (PDOException $e) {
                        if ($docStored) { @unlink(__DIR__ . '/../assets/movie_change_documents/' . $docStored); }
                        $error = isset($_POST['add_movie']) ? 'Error adding movie.' : 'Error updating movie.';
                    }
                }
            }
        } elseif (isset($_POST['delete_movie'])) {
            $movie_id = (int)$_POST['movie_id'];
            if ($is_super) {
                try {
                    $stmt = $pdo->prepare("SELECT title FROM movies WHERE movie_id = ?");
                    $stmt->execute([$movie_id]);
                    $movie = $stmt->fetch();
                    if (!$movie) {
                        $error = 'Movie not found.';
                    } else {
                        $stmt = $pdo->prepare("SELECT COUNT(*) FROM rentals WHERE movie_id = ? AND status = 'pending'");
                        $stmt->execute([$movie_id]);
                        if ($stmt->fetchColumn() > 0) { $error = 'Cannot delete movie with pending rentals.'; }
                        else {
                            $stmt = $pdo->prepare("DELETE FROM movies WHERE movie_id = ?");
                            $stmt->execute([$movie_id]);
                            log_audit($pdo, 'movie_deleted', 'movies', $movie_id, $movie['title'], 'Movie "' . $movie['title'] . '" (ID: ' . $movie_id . ') deleted by Super Admin');
                            $success = 'Movie deleted!';
                        }
                    }
                } catch (PDOException $e) { $error = 'Error deleting movie.'; }
            } else {
                $error = 'Only the Super Administrator can delete movies. Please submit a deletion request instead.';
            }
        } elseif (isset($_POST['request_delete_movie'])) {
            // Admins cannot delete movies directly; they must submit a deletion
            // request (reason + document + password) for Super Admin approval.
            $movie_id = (int)$_POST['movie_id'];
            $del_reason = trim($_POST['delete_reason'] ?? '');
            $del_password = $_POST['delete_admin_password'] ?? '';

            if ($del_reason === '') {
                $error = 'A reason is required for the deletion request.';
            } elseif ($del_password === '') {
                $error = 'Please enter your current password to confirm this action.';
            } elseif (!check_user_password($pdo, 'admin_users', $_SESSION['admin_id'], $del_password)) {
                $error = 'Inputted password is wrong.';
            } else {
                list($docStored, $docSafe, $docMime, $docErr) = handle_change_document_upload('delete_document');
                if ($docErr) {
                    $error = $docErr;
                } else {
                    try {
                        $stmt = $pdo->prepare("SELECT title FROM movies WHERE movie_id = ?");
                        $stmt->execute([$movie_id]);
                        $movie = $stmt->fetch();
                        if (!$movie) {
                            @unlink(__DIR__ . '/../assets/movie_change_documents/' . $docStored);
                            $error = 'Movie not found.';
                        } else {
                            $pdo->beginTransaction();
                            try {
                                $pdo->prepare("INSERT INTO movie_deletion_requests (movie_id, movie_title, reason, requested_by_id, requested_by_name) VALUES (?, ?, ?, ?, ?)")
                                    ->execute([$movie_id, $movie['title'], $del_reason, $_SESSION['admin_id'], $_SESSION['admin_full_name'] ?? '']);
                                $req_id = (int)$pdo->lastInsertId();
                                $pdo->prepare("INSERT INTO movie_deletion_documents (request_id, movie_id, file_path, original_name, file_size, mime_type) VALUES (?, ?, ?, ?, ?, ?)")
                                    ->execute([$req_id, $movie_id, $docStored, $docSafe, (int)($_FILES['delete_document']['size'] ?? 0), $docMime]);
                                log_audit($pdo, 'movie_deletion_request_created', 'movies', $movie_id, $movie['title'], 'Movie deletion request submitted for Super Admin review: ' . $del_reason);
                                $pdo->commit();
                                $success = 'Deletion request for <strong>' . htmlspecialchars($movie['title']) . '</strong> has been sent to the Super Admin for review. The movie is still in the catalog until the request is approved.';
                            } catch (PDOException $e) {
                                $pdo->rollBack();
                                @unlink(__DIR__ . '/../assets/movie_change_documents/' . $docStored);
                                error_log('[manage_movies] deletion request error: ' . $e->getMessage());
                                $error = 'Failed to submit the deletion request.';
                            }
                        }
                    } catch (PDOException $e) {
                        if ($docStored) { @unlink(__DIR__ . '/../assets/movie_change_documents/' . $docStored); }
                        $error = 'Error submitting the deletion request.';
                    }
                }
            }
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
                    <div><h1 class="page-title">Manage Movies</h1><p class="page-subtitle"><?php echo $is_super ? 'Add, edit, view, or remove movies from the catalog' : 'Add, view, and edit movies. Deletion requests require Super Admin approval.'; ?></p></div>
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
                                        <button class="btn btn-sm btn-outline" title="View details" onclick='openViewModal(<?php echo htmlspecialchars(json_encode($movie), ENT_QUOTES); ?>)'><i class="fas fa-eye"></i></button>
                                        <button class="btn btn-sm btn-outline" title="Edit" onclick='openEditModal(<?php echo htmlspecialchars(json_encode($movie), ENT_QUOTES); ?>)'><i class="fas fa-edit"></i></button>
<?php if ($is_super): ?>
                                        <button class="btn btn-sm btn-outline-danger" title="Delete" onclick="confirmDelete(<?php echo $movie['movie_id']; ?>,'<?php echo htmlspecialchars($movie['title'], ENT_QUOTES); ?>')"><i class="fas fa-trash"></i></button>
<?php else: ?>
                                        <button class="btn btn-sm btn-outline-danger" title="Request deletion" onclick="confirmRequestDelete(<?php echo $movie['movie_id']; ?>,'<?php echo htmlspecialchars($movie['title'], ENT_QUOTES); ?>')"><i class="fas fa-file-import"></i></button>
<?php endif; ?>
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
    <div id="viewModal" class="modal"><div class="modal-content" style="max-height:85vh;overflow-y:auto;"><div class="modal-header"><h3 class="modal-title"><i class="fas fa-film"></i> Movie Details</h3><span class="close" onclick="closeViewModal()">&times;</span></div><div class="modal-body">
        <div style="display:flex;gap:1.25rem;flex-wrap:wrap;">
            <div style="flex-shrink:0;">
                <img id="view_poster" style="width:160px;height:240px;object-fit:cover;border-radius:var(--radius);background:var(--background);">
            </div>
            <div style="flex:1;min-width:220px;display:grid;gap:0.5rem;align-content:start;">
                <div><strong>Title:</strong> <span id="view_title"></span></div>
                <div><strong>Genre:</strong> <span id="view_genre"></span></div>
                <div><strong>Release Year:</strong> <span id="view_release_year"></span></div>
                <div><strong>Director:</strong> <span id="view_director"></span></div>
                <div><strong>Cast:</strong> <span id="view_cast_members"></span></div>
                <div><strong>Duration:</strong> <span id="view_duration_minutes"></span></div>
                <div><strong>Rating:</strong> <span id="view_rating"></span></div>
                <div><strong>Rental Price:</strong> <span id="view_rental_price"></span></div>
                <div><strong>Status:</strong> <span id="view_status"></span></div>
            </div>
        </div>
        <div style="margin-top:1rem;"><strong>Description:</strong><p id="view_description" style="white-space:pre-wrap;margin-top:0.25rem;"></p></div>
        <div class="flex gap-3 mt-4">
            <button type="button" class="btn btn-outline" onclick="closeViewModal()" style="width:100%;"><i class="fas fa-times"></i> Close</button>
        </div>
    </div></div></div>
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
<?php if (!$is_super): ?>
            <div style="background:var(--surface-2);border:1px dashed var(--border);border-radius:var(--radius);padding:1rem;margin-top:0.5rem;">
                <label style="font-weight:700;font-size:0.8125rem;display:block;margin-bottom:0.25rem;"><i class="fas fa-shield-alt" style="color:var(--primary);"></i> Admin Edit Confirmation</label>
                <small style="display:block;color:var(--text-light);font-size:0.75rem;margin-bottom:0.75rem;">Editing a movie as an Admin requires a reason, a supporting document, and your password.</small>
                <div class="form-group"><label>Reason for this edit *</label><textarea name="change_reason" class="form-control" rows="2" required placeholder="Why is this edit being made?"></textarea></div>
                <div class="form-group"><label>Supporting Document * <small style="color:var(--text-light);">(PDF, JPG, PNG, WEBP — max 5MB)</small></label><input type="file" name="change_document" class="form-control" accept=".pdf,.jpg,.jpeg,.png,.webp" required></div>
                <div class="form-group" style="margin-bottom:0;"><label>Your Password (to confirm) *</label><input type="password" name="change_admin_password" class="form-control" autocomplete="off" placeholder="Enter YOUR current password to confirm" required></div>
            </div>
<?php endif; ?>
            <button type="submit" name="edit_movie" class="btn btn-success" style="width:100%;"><i class="fas fa-save"></i> Update Movie</button>
        </form>
    </div></div></div>
<?php if ($is_super): ?>
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
<?php else: ?>
    <div id="requestDeleteModal" class="modal"><div class="modal-content"><div class="modal-header"><h3 class="modal-title" style="color:var(--danger);"><i class="fas fa-file-import"></i> Request Movie Deletion</h3><span class="close" onclick="closeRequestDeleteModal()">&times;</span></div><div class="modal-body">
        <p>You are requesting the deletion of <strong>"<span id="request_delete_movie_name"></span>"</strong>.</p>
        <p style="font-size:0.8125rem;color:var(--text-light);"><i class="fas fa-info-circle"></i> Only the Super Administrator can delete movies. Your request will be reviewed; the movie stays in the catalog until the request is approved.</p>
        <form method="POST" action="" enctype="multipart/form-data" style="margin-top:1rem;">
            <?php csrf_token_input(); ?>
            <input type="hidden" id="request_delete_movie_id" name="movie_id">
            <div class="form-group"><label>Reason for deletion *</label><textarea name="delete_reason" class="form-control" rows="3" required placeholder="Why should this movie be deleted?"></textarea></div>
            <div class="form-group"><label>Supporting Document * <small style="color:var(--text-light);">(PDF, JPG, PNG, WEBP — max 5MB)</small></label><input type="file" name="delete_document" class="form-control" accept=".pdf,.jpg,.jpeg,.png,.webp" required></div>
            <div class="form-group"><label>Your Password (to confirm) *</label><input type="password" name="delete_admin_password" class="form-control" autocomplete="off" placeholder="Enter YOUR current password to confirm" required></div>
            <div class="flex gap-3 mt-4">
                <button type="button" class="btn btn-outline" onclick="closeRequestDeleteModal()" style="flex:1;"><i class="fas fa-times"></i> Cancel</button>
                <button type="submit" name="request_delete_movie" class="btn btn-danger" style="flex:1;" onclick="return confirm('Submit this deletion request to the Super Administrator?');"><i class="fas fa-paper-plane"></i> Send Request</button>
            </div>
        </form>
    </div></div></div>
<?php endif; ?>
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
        function confirmDelete(id, name) { var m = document.getElementById('deleteModal'); if (!m) return; document.getElementById('delete_movie_id').value = id; document.getElementById('delete_movie_name').textContent = name; m.style.display = 'flex'; }
        function closeDeleteModal() { var m = document.getElementById('deleteModal'); if (m) m.style.display = 'none'; }
        function confirmRequestDelete(id, name) { var m = document.getElementById('requestDeleteModal'); if (!m) return; document.getElementById('request_delete_movie_id').value = id; document.getElementById('request_delete_movie_name').textContent = name; m.style.display = 'flex'; }
        function closeRequestDeleteModal() { var m = document.getElementById('requestDeleteModal'); if (m) m.style.display = 'none'; }
        function openViewModal(movie) {
            var poster = document.getElementById('view_poster');
            poster.src = movie.poster || '';
            poster.style.display = movie.poster ? 'block' : 'none';
            document.getElementById('view_title').textContent = movie.title || '';
            document.getElementById('view_genre').textContent = movie.genre || '—';
            document.getElementById('view_release_year').textContent = movie.release_year || '—';
            document.getElementById('view_director').textContent = movie.director || '—';
            document.getElementById('view_cast_members').textContent = movie.cast_members || '—';
            document.getElementById('view_duration_minutes').textContent = movie.duration_minutes ? movie.duration_minutes + ' min' : '—';
            document.getElementById('view_rating').textContent = (movie.rating !== null && movie.rating !== undefined) ? Number(movie.rating).toFixed(1) + ' / 10' : '—';
            document.getElementById('view_rental_price').textContent = '<?php echo CURRENCY_SYMBOL; ?>' + Number(movie.rental_price).toFixed(2);
            document.getElementById('view_status').textContent = (movie.status || '').charAt(0).toUpperCase() + (movie.status || '').slice(1);
            document.getElementById('view_description').textContent = movie.description || 'No description provided.';
            document.getElementById('viewModal').style.display = 'flex';
        }
        function closeViewModal() { document.getElementById('viewModal').style.display = 'none'; }
        window.onclick = function(e) { ['viewModal','addModal','editModal','deleteModal','requestDeleteModal'].forEach(function(id) { var m = document.getElementById(id); if (m && e.target == m) m.style.display = 'none'; }); };
        (function(){ var f=document.getElementById('edit_poster'),p=document.getElementById('edit_poster_preview'); if(f) f.addEventListener('change',function(){ var file=f.files&&f.files[0]; if(file&&p) p.src=URL.createObjectURL(file); }); })();
    </script>
</body>
</html>
