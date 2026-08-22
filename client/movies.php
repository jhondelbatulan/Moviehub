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

// --- Filters ---
$search = isset($_GET['search']) ? trim($_GET['search']) : '';
$genre_filter = isset($_GET['genre']) ? (int)$_GET['genre'] : 0;
$year_filter = isset($_GET['year']) ? trim($_GET['year']) : '';
$rating_filter = isset($_GET['rating']) ? (float)$_GET['rating'] : 0;
$availability_filter = isset($_GET['availability']) ? $_GET['availability'] : '';

$where = [];
$params = [];
if ($search !== '') {
    $sp = '%' . $search . '%';
    $where[] = "(m.title LIKE ? OR g.name LIKE ? OR m.director LIKE ?)";
    array_push($params, $sp, $sp, $sp);
}
if ($genre_filter > 0) { $where[] = "m.genre_id = ?"; $params[] = $genre_filter; }
if ($year_filter !== '' && ctype_digit($year_filter)) { $where[] = "m.release_year = ?"; $params[] = (int)$year_filter; }
if ($rating_filter > 0) { $where[] = "m.rating >= ?"; $params[] = $rating_filter; }
if (in_array($availability_filter, ['available', 'rented', 'maintenance'], true)) { $where[] = "m.status = ?"; $params[] = $availability_filter; }
$where_clause = !empty($where) ? 'WHERE ' . implode(' AND ', $where) : '';

try {
    $stmt = $pdo->prepare("SELECT m.*, g.name AS genre FROM movies m LEFT JOIN genres g ON m.genre_id = g.id $where_clause ORDER BY m.title");
    $stmt->execute($params);
    $movies = $stmt->fetchAll();
} catch (PDOException $e) { $movies = []; }

try { $genres = $pdo->query("SELECT id, name FROM genres ORDER BY name")->fetchAll(); } catch (PDOException $e) { $genres = []; }
try { $years = $pdo->query("SELECT DISTINCT release_year FROM movies WHERE release_year IS NOT NULL ORDER BY release_year DESC")->fetchAll(PDO::FETCH_COLUMN); } catch (PDOException $e) { $years = []; }

$pending_count = 0;
try { $pending_count = $pdo->query("SELECT COUNT(*) FROM rentals WHERE user_id = " . (int)$_SESSION['user_id'] . " AND status = 'pending'")->fetchColumn(); } catch (Exception $e) {}

try { $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$_SESSION['user_id']]); $user = $stmt->fetch(); } catch (PDOException $e) { $user = null; }

generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Movie Library - MovieHub</title>
    <link rel="stylesheet" href="../assets/css/style.css?v=2.3.0">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body>
    <?php require_once '../includes/navbar.php'; ?>
    <main class="mh-main">
        <div class="mh-page-head">
            <div>
                <h1 class="page-title">Movie Library</h1>
                <p class="page-subtitle">Browse, search, and rent movies</p>
            </div>
            <div class="header-actions"><span class="text-sm text-muted"><i class="fas fa-calendar"></i> <?php echo date('M d, Y'); ?></span></div>
        </div>

        <a id="genres-filter"></a>
        <div class="content-body">
                <div class="card" style="margin-bottom:1.5rem;">
                    <div class="card-body" style="padding:1rem 1.5rem;">
                        <form method="GET" action="" style="display:flex;flex-wrap:wrap;gap:0.75rem;align-items:flex-end;">
                            <div class="form-group" style="flex:2;min-width:200px;margin-bottom:0;">
                                <label>Search</label>
                                <input type="text" name="search" class="form-control" placeholder="Search by title, genre, or director..." value="<?php echo htmlspecialchars($search); ?>">
                            </div>
                            <div class="form-group" style="flex:1;min-width:140px;margin-bottom:0;">
                                <label>Genre</label>
                                <select name="genre" class="form-control">
                                    <option value="">All Genres</option>
                                    <?php foreach ($genres as $g): ?><option value="<?php echo (int)$g['id']; ?>" <?php echo $genre_filter === (int)$g['id'] ? 'selected' : ''; ?>><?php echo htmlspecialchars($g['name']); ?></option><?php endforeach; ?>
                                </select>
                            </div>
                            <div class="form-group" style="flex:1;min-width:120px;margin-bottom:0;">
                                <label>Year</label>
                                <select name="year" class="form-control">
                                    <option value="">All Years</option>
                                    <?php foreach ($years as $y): ?><option value="<?php echo (int)$y; ?>" <?php echo $year_filter === (string)$y ? 'selected' : ''; ?>><?php echo (int)$y; ?></option><?php endforeach; ?>
                                </select>
                            </div>
                            <div class="form-group" style="flex:1;min-width:130px;margin-bottom:0;">
                                <label>Rating</label>
                                <select name="rating" class="form-control">
                                    <option value="">Any Rating</option>
                                    <?php foreach ([9, 8, 7, 6, 5] as $r): ?><option value="<?php echo $r; ?>" <?php echo $rating_filter === (float)$r ? 'selected' : ''; ?>><?php echo $r; ?>+ Stars</option><?php endforeach; ?>
                                </select>
                            </div>
                            <div class="form-group" style="flex:1;min-width:140px;margin-bottom:0;">
                                <label>Availability</label>
                                <select name="availability" class="form-control">
                                    <option value="">All</option>
                                    <option value="available" <?php echo $availability_filter === 'available' ? 'selected' : ''; ?>>Available</option>
                                    <option value="rented" <?php echo $availability_filter === 'rented' ? 'selected' : ''; ?>>Rented</option>
                                    <option value="maintenance" <?php echo $availability_filter === 'maintenance' ? 'selected' : ''; ?>>Maintenance</option>
                                </select>
                            </div>
                            <button type="submit" class="btn btn-primary btn-sm" style="height:2.5rem;"><i class="fas fa-search"></i> Apply</button>
                            <a href="movies.php" class="btn btn-outline btn-sm" style="height:2.5rem;"><i class="fas fa-times"></i> Clear</a>
                        </form>
                    </div>
                </div>

                <p class="text-sm text-muted" style="margin-bottom:1rem;"><?php echo count($movies); ?> movie<?php echo count($movies) === 1 ? '' : 's'; ?> found</p>

                <div class="movie-grid">
<?php foreach ($movies as $movie): ?>
                    <div class="movie-card">
                        <a href="movie_details.php?id=<?php echo (int)$movie['movie_id']; ?>" class="movie-poster" style="display:block;">
                            <?php if (!empty($movie['poster'])): ?>
                                <img src="<?php echo htmlspecialchars($movie['poster']); ?>" alt="<?php echo htmlspecialchars($movie['title']); ?>" style="width:100%;height:100%;object-fit:cover;">
                            <?php else: ?>
                                <i class="fas fa-film"></i>
                            <?php endif; ?>
                        </a>
                        <div class="movie-info">
                            <div class="movie-title"><?php echo htmlspecialchars($movie['title']); ?></div>
                            <div class="movie-meta">
                                <span><i class="fas fa-tag"></i> <?php echo htmlspecialchars($movie['genre'] ?? 'Uncategorized'); ?></span>
                                <?php if (!empty($movie['release_year'])): ?><span><i class="fas fa-calendar"></i> <?php echo (int)$movie['release_year']; ?></span><?php endif; ?>
                                <?php if ($movie['rating'] !== null && $movie['rating'] !== ''): ?><span><i class="fas fa-star" style="color:#f59e0b;"></i> <?php echo number_format((float)$movie['rating'], 1); ?></span><?php endif; ?>
                            </div>
                            <div class="movie-price"><?php echo CURRENCY_SYMBOL . number_format((float)$movie['rental_price'], 2); ?><small>/day</small></div>
                        </div>
                        <div class="movie-footer">
                            <span class="status-badge status-<?php echo htmlspecialchars($movie['status']); ?>"><?php echo ucfirst(htmlspecialchars($movie['status'])); ?></span>
                            <div style="display:flex;gap:0.375rem;">
                                <a href="movie_details.php?id=<?php echo (int)$movie['movie_id']; ?>" class="btn btn-sm btn-outline"><i class="fas fa-info-circle"></i> Details</a>
                                <?php if ($movie['status'] === 'available'): ?>
                                    <a href="dashboard.php?rent=<?php echo (int)$movie['movie_id']; ?>" class="btn btn-sm btn-primary"><i class="fas fa-calendar-plus"></i> Rent Now</a>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
<?php endforeach; ?>
<?php if (empty($movies)): ?>
                    <div class="empty-state" style="grid-column:1/-1;"><i class="fas fa-search"></i><h3>No Movies Found</h3><p>Try adjusting your search or filters.</p></div>
<?php endif; ?>
                </div>
        </div>
    </main>
</body>
</html>
