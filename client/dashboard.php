<?php
session_start();
require_once '../config.php';
require_once '../db_connect.php';
require_once '../includes/functions.php';
require_once '../includes/authorization.php';
require_once '../includes/csrf.php';

require_login();
require_role('user');
require_status_active();

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['request_movie'])) {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error_message = 'Invalid security token. Please try again.';
    } else {
        $movie_id = (int)$_POST['movie_id'];
        $rental_date = $_POST['rental_date'];
        $expected_days = isset($_POST['expected_days']) ? (int)$_POST['expected_days'] : 0;
        if ($expected_days < 1) { $error_message = "Please enter a valid number of days."; }
        elseif (empty($rental_date) || strtotime($rental_date) === false) { $error_message = "Please choose a valid rental date."; }
        else {
            try {
                $stmt = $pdo->prepare("SELECT rental_price FROM movies WHERE movie_id = ? AND status = 'available'");
                $stmt->execute([$movie_id]);
                $movie = $stmt->fetch();
                if ($movie) {
                    $start = new DateTime($rental_date);
                    $due = (clone $start)->modify('+' . ($expected_days - 1) . ' days');
                    $total_amount = (float)$movie['rental_price'] * $expected_days;
                    $stmt = $pdo->prepare("INSERT INTO rentals (user_id, movie_id, rental_date, due_date, rental_price) VALUES (?, ?, ?, ?, ?)");
                    $stmt->execute([$_SESSION['user_id'], $movie_id, $start->format('Y-m-d'), $due->format('Y-m-d'), $total_amount]);
                    $success_message = "Rental request submitted successfully!";
                } else { $error_message = "Movie not available for rental."; }
            } catch (PDOException $e) { $error_message = "Error submitting request."; }
        }
    }
}

try {
    $stmt = $pdo->prepare("SELECT m.*, g.name AS genre FROM movies m LEFT JOIN genres g ON m.genre_id = g.id WHERE m.status = 'available' OR m.movie_id IN (SELECT movie_id FROM rentals WHERE user_id = ? AND returned_at IS NULL AND status IN ('pending','approved')) ORDER BY m.title");
    $stmt->execute([$_SESSION['user_id']]);
    $movies = $stmt->fetchAll();
} catch (PDOException $e) { $movies = []; }
try { $available_count = (int)$pdo->query("SELECT COUNT(*) FROM movies WHERE status = 'available'")->fetchColumn(); } catch (PDOException $e) { $available_count = 0; }
try {
    $stmt = $pdo->prepare("SELECT r.*, m.title, m.poster, g.name AS genre, m.rental_price AS daily_price FROM rentals r JOIN movies m ON r.movie_id = m.movie_id LEFT JOIN genres g ON m.genre_id = g.id WHERE r.user_id = ? ORDER BY r.created_at DESC");
    $stmt->execute([$_SESSION['user_id']]);
    $rental_requests = $stmt->fetchAll();
} catch (PDOException $e) { $rental_requests = []; }
$my_rental_status = [];
foreach ($rental_requests as $r) {
    if (!empty($r['returned_at'])) continue;
    if ($r['status'] == 'pending' || $r['status'] == 'approved') { $my_rental_status[(int)$r['movie_id']] = $r['status']; }
}

// Deep-link: ?rent=MOVIE_ID pre-opens the rental modal
$rent_movie = null;
if (isset($_GET['rent'])) {
    $rent_id = (int)$_GET['rent'];
    if ($rent_id > 0) {
        try {
            $stmt = $pdo->prepare("SELECT movie_id, title, rental_price FROM movies WHERE movie_id = ? AND status = 'available'");
            $stmt->execute([$rent_id]);
            $rent_movie = $stmt->fetch();
        } catch (PDOException $e) { $rent_movie = null; }
    }
}

$pending_count = 0;
foreach ($rental_requests as $r) { if ($r['status'] == 'pending') $pending_count++; }

try { $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$_SESSION['user_id']]); $user = $stmt->fetch(); } catch (PDOException $e) { $user = null; }
$profile_data = $user ?: [];
$active_count = 0;
$completed_count = 0;
foreach ($rental_requests as $r) {
    if ($r['status'] == 'approved') $active_count++;
    elseif ($r['status'] != 'pending') $completed_count++;
}

generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - MovieHub</title>
    <link rel="stylesheet" href="../assets/css/style.css?v=2.3.0">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body>
    <?php require_once '../includes/navbar.php'; ?>
    <main class="mh-main">
        <div class="mh-page-head">
            <div>
                <h1 class="page-title">Dashboard</h1>
                <p class="page-subtitle">Welcome back, <?php echo htmlspecialchars($_SESSION['full_name']); ?>!</p>
            </div>
            <div class="header-actions" style="display:flex;align-items:center;gap:0.75rem;"><span class="text-sm text-muted"><i class="fas fa-calendar"></i> <?php echo date('M d, Y'); ?></span><a href="logout.php" class="btn btn-sm btn-outline"><i class="fas fa-sign-out-alt"></i> Logout</a></div>
        </div>

            <div class="content-body">
                <?php if (isset($success_message)): ?><div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($success_message); ?></div><?php endif; ?>
                <?php if (isset($error_message)): ?><div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error_message); ?></div><?php endif; ?>

                <div class="grid grid-3" style="margin-bottom:1.5rem;">
                    <div class="stat-card"><div class="stat-card-icon green"><i class="fas fa-film"></i></div><div class="stat-card-value"><?php echo $available_count; ?></div><div class="stat-card-label">Available Movies</div></div>
                    <div class="stat-card"><div class="stat-card-icon amber"><i class="fas fa-clock"></i></div><div class="stat-card-value"><?php echo $pending_count; ?></div><div class="stat-card-label">Pending Requests</div></div>
                    <div class="stat-card"><div class="stat-card-icon blue"><i class="fas fa-check-circle"></i></div><div class="stat-card-value"><?php echo $active_count; ?></div><div class="stat-card-label">Active Rentals</div></div>
                </div>

                <h3 style="margin-bottom:1rem;"><i class="fas fa-film"></i> Available Movies <a href="movies.php" class="btn btn-sm btn-outline" style="margin-left:0.5rem;"><i class="fas fa-th-large"></i> Browse Library</a></h3>
                <div class="movie-grid" style="margin-bottom:2rem;">
<?php foreach ($movies as $movie): ?>
                    <div class="movie-card">
                        <div class="movie-poster">
                            <?php if (!empty($movie['poster'])): ?>
                                <img src="<?php echo htmlspecialchars($movie['poster']); ?>" alt="<?php echo htmlspecialchars($movie['title']); ?>">
                            <?php else: ?>
                                <i class="fas fa-film"></i>
                            <?php endif; ?>
                        </div>
                        <div class="movie-info">
                            <div class="movie-title"><?php echo htmlspecialchars($movie['title']); ?></div>
                            <div class="movie-meta">
                                <span><i class="fas fa-tag"></i> <?php echo htmlspecialchars($movie['genre'] ?? ''); ?></span>
                            </div>
                            <div class="movie-price"><?php echo CURRENCY_SYMBOL . number_format($movie['rental_price'], 2); ?><small>/day</small></div>
                        </div>
                        <div class="movie-footer">
                            <span class="text-sm text-muted"><?php echo htmlspecialchars(substr($movie['description'] ?? '', 0, 50)); ?><?php echo strlen($movie['description'] ?? '') > 50 ? '...' : ''; ?></span>
<?php $mine = $my_rental_status[(int)$movie['movie_id']] ?? null; ?>
                            <?php if ($mine === 'approved'): ?><span class="status-badge status-approved"><i class="fas fa-check-circle"></i> Rented by You</span>
                            <?php elseif ($mine === 'pending'): ?><span class="status-badge status-pending"><i class="fas fa-clock"></i> Pending</span>
                            <?php else: ?><button class="btn btn-sm btn-primary" onclick="openRentalModal(<?php echo $movie['movie_id']; ?>,'<?php echo htmlspecialchars($movie['title'],ENT_QUOTES); ?>',<?php echo $movie['rental_price']; ?>)"><i class="fas fa-calendar-plus"></i> Rent</button><?php endif; ?>
                        </div>
                    </div>
<?php endforeach; ?>
<?php if (empty($movies)): ?>
                    <div class="empty-state" style="grid-column:1/-1;"><i class="fas fa-film"></i><h3>No Movies Available</h3><p>Check back later for available movies.</p></div>
<?php endif; ?>
                </div>

                <h3 id="my-rentals" style="margin-bottom:1rem;"><i class="fas fa-clipboard-list"></i> My Rentals</h3>
                <div class="card">
<?php if (!empty($rental_requests)): ?>
                    <div class="table-responsive">
                        <table class="table">
                            <thead><tr><th>Poster</th><th>Movie</th><th>Genre</th><th>Rental Date</th><th>Due / Returned</th><th>Price</th><th>Status</th><th>Admin Notes</th></tr></thead>
                            <tbody>
<?php foreach ($rental_requests as $request): ?>
                                <tr>
                                    <td><?php if (!empty($request['poster'])): ?><img src="<?php echo htmlspecialchars($request['poster']); ?>" style="width:40px;height:56px;object-fit:cover;border-radius:var(--radius);"><?php else: ?><div style="width:40px;height:56px;background:var(--background);border-radius:var(--radius);display:flex;align-items:center;justify-content:center;"><i class="fas fa-film" style="color:var(--muted);"></i></div><?php endif; ?></td>
                                    <td><strong><?php echo htmlspecialchars($request['title']); ?></strong></td>
                                    <td><?php echo htmlspecialchars($request['genre'] ?? ''); ?></td>
                                    <td><?php echo date('M d, Y', strtotime($request['rental_date'])); ?></td>
                                    <td><?php if (!empty($request['returned_at'])): ?><span class="status-badge status-approved"><i class="fas fa-undo"></i> <?php echo date('M d, Y', strtotime($request['returned_at'])); ?></span><?php elseif (!empty($request['due_date'])): ?><?php echo date('M d, Y', strtotime($request['due_date'])); ?><?php else: ?>—<?php endif; ?></td>
                                    <td><strong><?php echo CURRENCY_SYMBOL.number_format($request['rental_price'],2); ?></strong></td>
                                    <td><span class="status-badge status-<?php echo $request['status']; ?>"><?php echo ucfirst($request['status']); ?></span></td>
                                    <td><small><?php echo !empty($request['admin_notes']) ? htmlspecialchars($request['admin_notes']) : '<span class="text-muted">No message</span>'; ?></small></td>
                                </tr>
<?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
<?php else: ?>
                    <div class="empty-state"><i class="fas fa-clipboard"></i><h3>No Rentals Yet</h3><p>Browse the movie library and make your first rental request.</p></div>
<?php endif; ?>
                </div>
            </div>
    </main>

    <div id="rentalModal" class="modal"><div class="modal-content"><div class="modal-header"><h3 class="modal-title">Rent Movie</h3><span class="close" onclick="closeRentalModal()">&times;</span></div><div class="modal-body">
        <form method="POST" action="">
            <?php csrf_token_input(); ?>
            <input type="hidden" id="modal_movie_id" name="movie_id">
            <div class="form-group"><label>Movie</label><input type="text" id="modal_movie_name" class="form-control" readonly></div>
            <div class="form-group"><label>Rental Date *</label><input type="date" id="rental_date" name="rental_date" class="form-control" required></div>
            <div class="form-group"><label>Expected Days *</label><input type="number" id="expected_days" name="expected_days" class="form-control" min="1" step="1" placeholder="e.g., 3" required></div>
            <div class="form-group"><label>Total Amount</label><input type="text" id="total_amount" class="form-control" readonly></div>
            <button type="submit" name="request_movie" class="btn btn-primary" style="width:100%;"><i class="fas fa-calendar-plus"></i> Submit Request</button>
        </form>
    </div></div></div>
    <script>
        var currentMoviePrice = 0;
        function openRentalModal(id, name, price) {
            document.getElementById('modal_movie_id').value = id;
            document.getElementById('modal_movie_name').value = name;
            currentMoviePrice = price;
            document.getElementById('rentalModal').style.display = 'flex';
            document.getElementById('rental_date').min = new Date().toISOString().split('T')[0];
        }
        function closeRentalModal() { document.getElementById('rentalModal').style.display = 'none'; }
        document.getElementById('rental_date').addEventListener('change', calcTotal);
        document.getElementById('expected_days').addEventListener('input', calcTotal);
        function calcTotal() {
            var d = parseInt(document.getElementById('expected_days').value || '0', 10);
            document.getElementById('total_amount').value = d > 0 ? '<?php echo CURRENCY_SYMBOL; ?>' + (currentMoviePrice * d).toFixed(2) : '';
        }
window.onclick = function(e) { if (e.target == document.getElementById('rentalModal')) closeRentalModal(); };
        <?php if ($rent_movie): ?>
        openRentalModal(<?php echo (int)$rent_movie['movie_id']; ?>, <?php echo json_encode(htmlspecialchars($rent_movie['title'], ENT_QUOTES)); ?>, <?php echo (float)$rent_movie['rental_price']; ?>);
        <?php endif; ?>
    </script>
</body>
</html>
