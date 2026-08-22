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

$movie_id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
$movie = null;
if ($movie_id > 0) {
    try {
        $stmt = $pdo->prepare("SELECT m.*, g.name AS genre FROM movies m LEFT JOIN genres g ON m.genre_id = g.id WHERE m.movie_id = ?");
        $stmt->execute([$movie_id]);
        $movie = $stmt->fetch();
    } catch (PDOException $e) { $movie = null; }
}

try { $stmt = $pdo->prepare("SELECT COUNT(*) FROM rentals WHERE user_id = ? AND status = 'pending'"); $stmt->execute([$_SESSION['user_id']]); $pending_count = (int)$stmt->fetchColumn(); } catch (Exception $e) { $pending_count = 0; }
try { $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$_SESSION['user_id']]); $user = $stmt->fetch(); } catch (PDOException $e) { $user = null; }

generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $movie ? htmlspecialchars($movie['title']) . ' - MovieHub' : 'Movie Not Found - MovieHub'; ?></title>
    <link rel="stylesheet" href="../assets/css/style.css?v=2.3.0">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body>
    <?php require_once '../includes/navbar.php'; ?>
    <main class="mh-main">
        <div class="mh-page-head">
            <div>
                <h1 class="page-title">Movie Details</h1>
                <p class="page-subtitle"><a href="movies.php" class="text-muted"><i class="fas fa-arrow-left"></i> Back to Movie Library</a></p>
            </div>
        </div>

        <div class="content-body">
<?php if (!$movie): ?>
                <div class="empty-state card" style="padding:3rem;"><i class="fas fa-film"></i><h3>Movie Not Found</h3><p>The movie you are looking for does not exist or was removed.</p><a href="movies.php" class="btn btn-primary" style="margin-top:1rem;">Browse Movies</a></div>
<?php else: ?>
                <div class="mh-detail-backdrop">
                    <div class="mh-detail-grid">
                        <div>
                            <div class="mh-detail-poster">
                                <?php if (!empty($movie['poster'])): ?>
                                    <img src="<?php echo htmlspecialchars($movie['poster']); ?>" alt="<?php echo htmlspecialchars($movie['title']); ?>">
                                <?php else: ?>
                                    <i class="fas fa-film"></i>
                                <?php endif; ?>
                            </div>
                        </div>
                        <div class="mh-detail-info">
                            <div class="flex items-center gap-2" style="flex-wrap:wrap;margin-bottom:0.5rem;">
                                <span class="status-badge status-<?php echo htmlspecialchars($movie['status']); ?>"><?php echo ucfirst(htmlspecialchars($movie['status'])); ?></span>
                                <?php if ($movie['genre']): ?><span class="badge badge-info"><i class="fas fa-tag"></i> <?php echo htmlspecialchars($movie['genre']); ?></span><?php endif; ?>
                            </div>
                            <h2><?php echo htmlspecialchars($movie['title']); ?></h2>
                            <?php if (!empty($movie['description'])): ?><p style="color:var(--text-light);margin-bottom:0.75rem;line-height:1.7;"><?php echo nl2br(htmlspecialchars($movie['description'])); ?></p><?php endif; ?>

                            <div class="mh-spec-grid">
                                <div class="mh-spec"><small>Release Year</small><div><?php echo $movie['release_year'] ? (int)$movie['release_year'] : '—'; ?></div></div>
                                <div class="mh-spec"><small>Director</small><div><?php echo $movie['director'] !== '' && $movie['director'] !== null ? htmlspecialchars($movie['director']) : '—'; ?></div></div>
                                <div class="mh-spec"><small>Duration</small><div><?php echo $movie['duration_minutes'] ? (int)$movie['duration_minutes'] . ' min' : '—'; ?></div></div>
                                <div class="mh-spec"><small>Rating</small><div><?php echo $movie['rating'] !== null ? '<i class="fas fa-star" style="color:#ffd166;"></i> ' . number_format((float)$movie['rating'], 1) . ' / 10' : '—'; ?></div></div>
                            </div>

                            <?php if (!empty($movie['cast_members'])): ?>
                            <p style="color:var(--text-light);line-height:1.7;margin-bottom:0.75rem;"><strong style="color:var(--text);">Cast:</strong> <?php echo htmlspecialchars($movie['cast_members']); ?></p>
                            <?php endif; ?>

                            <div style="display:flex;align-items:center;gap:1.25rem;flex-wrap:wrap;padding-top:1.25rem;border-top:1px solid var(--border);">
                                <div>
                                    <small class="text-muted">Rental Price</small>
                                    <div class="movie-price" style="font-size:1.6rem;"><?php echo CURRENCY_SYMBOL . number_format((float)$movie['rental_price'], 2); ?><small>/day</small></div>
                                </div>
                                <?php if ($movie['status'] === 'available'): ?>
                                    <a href="dashboard.php?rent=<?php echo (int)$movie['movie_id']; ?>" class="btn btn-primary" style="padding:0.8rem 2.2rem;border-radius:999px;"><i class="fas fa-calendar-plus"></i> Rent Now</a>
                                <?php else: ?>
                                    <button class="btn btn-outline" style="padding:0.8rem 2rem;" disabled><i class="fas fa-ban"></i> Currently Unavailable</button>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>
<?php endif; ?>
        </div>
    </main>
</body>
</html>
