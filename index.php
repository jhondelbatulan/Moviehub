<?php
require_once 'config.php';
require_once 'db_connect.php';
require_once 'includes/functions.php';

// Featured: top-rated available movies
try {
    $featured = $pdo->query("SELECT m.movie_id, m.title, m.poster, m.release_year, m.rating, m.rental_price, m.status, g.name AS genre FROM movies m LEFT JOIN genres g ON m.genre_id = g.id WHERE m.status = 'available' AND m.rating IS NOT NULL ORDER BY m.rating DESC, m.created_at DESC LIMIT 8")->fetchAll();
} catch (PDOException $e) { $featured = []; }

// Popular: most rented movies
try {
    $popular = $pdo->query("SELECT m.movie_id, m.title, m.poster, m.release_year, m.rating, m.rental_price, m.status, g.name AS genre, COUNT(r.rental_id) AS rental_count FROM movies m LEFT JOIN genres g ON m.genre_id = g.id LEFT JOIN rentals r ON r.movie_id = m.movie_id GROUP BY m.movie_id, m.title, m.poster, m.release_year, m.rating, m.rental_price, m.status, g.name ORDER BY rental_count DESC, m.rating DESC LIMIT 8")->fetchAll();
} catch (PDOException $e) { $popular = []; }

// Recently added
try {
    $recent = $pdo->query("SELECT m.movie_id, m.title, m.poster, m.release_year, m.rating, m.rental_price, m.status, g.name AS genre FROM movies m LEFT JOIN genres g ON m.genre_id = g.id ORDER BY m.created_at DESC LIMIT 8")->fetchAll();
} catch (PDOException $e) { $recent = []; }

try { $total_movies = $pdo->query("SELECT COUNT(*) FROM movies")->fetchColumn(); } catch (Exception $e) { $total_movies = 0; }
try { $total_genres = $pdo->query("SELECT COUNT(*) FROM genres")->fetchColumn(); } catch (Exception $e) { $total_genres = 0; }
try { $total_rentals = $pdo->query("SELECT COUNT(*) FROM rentals WHERE status = 'approved'")->fetchColumn(); } catch (Exception $e) { $total_rentals = 0; }

function mh_movie_card(array $movie): void {
    $detailUrl = 'client/movie_details.php?id=' . (int)$movie['movie_id'];
    $rentUrl = 'client/dashboard.php?rent=' . (int)$movie['movie_id'];
    ?>
    <div class="movie-card">
        <a href="<?php echo $detailUrl; ?>" class="movie-poster">
            <?php if (!empty($movie['poster'])): ?>
                <img src="<?php echo htmlspecialchars(movie_poster_url($movie['poster'])); ?>" alt="<?php echo htmlspecialchars($movie['title']); ?>" loading="lazy">
            <?php else: ?>
                <span class="ph-fallback"><i class="fas fa-film"></i></span>
            <?php endif; ?>
            <?php if ($movie['rating'] !== null && $movie['rating'] !== ''): ?>
                <span class="movie-rating"><i class="fas fa-star"></i> <?php echo number_format((float)$movie['rating'], 1); ?></span>
            <?php endif; ?>
            <span class="status-badge status-<?php echo htmlspecialchars($movie['status']); ?> movie-status"><?php echo ucfirst(htmlspecialchars($movie['status'])); ?></span>
        </a>
        <div class="movie-body">
            <h3 class="movie-title" title="<?php echo htmlspecialchars($movie['title']); ?>"><?php echo htmlspecialchars($movie['title']); ?></h3>
            <div class="movie-meta">
                <span><i class="fas fa-tag"></i> <?php echo htmlspecialchars($movie['genre'] ?? 'Uncategorized'); ?></span>
                <?php if (!empty($movie['release_year'])): ?><span><i class="fas fa-calendar"></i> <?php echo (int)$movie['release_year']; ?></span><?php endif; ?>
            </div>
            <div class="movie-price"><?php echo CURRENCY_SYMBOL . number_format((float)$movie['rental_price'], 2); ?><small>/day</small></div>
        </div>
        <div class="movie-foot">
            <a href="<?php echo $detailUrl; ?>" class="btn btn-sm btn-outline"><i class="fas fa-info-circle"></i> Details</a>
            <?php if ($movie['status'] === 'available'): ?>
                <a href="<?php echo $rentUrl; ?>" class="btn btn-sm btn-primary"><i class="fas fa-calendar-plus"></i> Rent</a>
            <?php endif; ?>
        </div>
    </div>
    <?php
}

$mh_isGuest = !isset($_SESSION['user_id']) && !isset($_SESSION['admin_id']) && !isset($_SESSION['super_admin_id']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MovieHub - Movie Rental System</title>
    <link rel="stylesheet" href="assets/css/style.css?v=2.3.0">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
</head>
<body class="mh-home">
    <?php require_once 'includes/header_public.php'; ?>

    <main>
        <section class="mh-hero">
            <div class="mh-hero-content">
                <span class="mh-hero-kicker"><i class="fas fa-clapperboard"></i> Movie Rental System</span>
                <h1 class="mh-hero-title">Movie<em>Hub</em><br>Your next movie is waiting.</h1>
                <p class="mh-hero-sub">
                    Browse a curated library of timeless classics and fresh blockbusters.
                    Rent by the hour at prices you'll love, get instant approval,
                    and track every rental in real time — all in one place.
                </p>
                <div class="mh-hero-actions">
                    <a href="client/movies.php" class="btn btn-primary" style="padding:0.9rem 2.4rem;font-size:1.02rem;border-radius:999px;">
                        <i class="fas fa-film"></i> Browse Movies
                    </a>
                    <?php if ($mh_isGuest): ?>
                        <a href="client/register.php" class="btn btn-outline" style="padding:0.9rem 2rem;font-size:1.02rem;border-radius:999px;background:rgba(255,255,255,0.06);border-color:rgba(255,255,255,0.35);color:#fff;">
                            Create Free Account
                        </a>
                    <?php endif; ?>
                </div>
                <div class="mh-hero-stats">
                    <div class="mh-stat"><b><?php echo (int)$total_movies; ?></b><span>Movies Available</span></div>
                    <div class="mh-stat"><b><?php echo (int)$total_genres; ?></b><span>Genres</span></div>
                    <div class="mh-stat"><b><?php echo (int)$total_rentals; ?></b><span>Rentals Completed</span></div>
                </div>
            </div>
        </section>

        <section class="mh-section">
            <div class="mh-section-head">
                <h2><i class="fas fa-star"></i> Featured Movies</h2>
                <a href="client/movies.php">View All <i class="fas fa-arrow-right"></i></a>
            </div>
            <div class="movie-grid">
<?php foreach ($featured as $movie) { mh_movie_card($movie); } ?>
<?php if (empty($featured)): ?>
                <div class="empty-state" style="grid-column:1/-1;"><i class="fas fa-film"></i><h3>No Movies Yet</h3><p>The library is being stocked. Check back soon!</p></div>
<?php endif; ?>
            </div>
        </section>

        <section class="mh-section">
            <div class="mh-section-head">
                <h2><i class="fas fa-fire" style="color:#ff4d6d;"></i> Popular Movies</h2>
                <a href="client/movies.php">View All <i class="fas fa-arrow-right"></i></a>
            </div>
            <div class="movie-grid">
<?php foreach ($popular as $movie) { mh_movie_card($movie); } ?>
<?php if (empty($popular)): ?>
                <div class="empty-state" style="grid-column:1/-1;"><i class="fas fa-fire"></i><h3>No Rentals Yet</h3><p>Be the first to rent a movie!</p></div>
<?php endif; ?>
            </div>
        </section>

        <section class="mh-section">
            <div class="mh-section-head">
                <h2><i class="fas fa-plus-circle" style="color:#34d399;"></i> Recently Added</h2>
                <a href="client/movies.php">View All <i class="fas fa-arrow-right"></i></a>
            </div>
            <div class="movie-grid">
<?php foreach ($recent as $movie) { mh_movie_card($movie); } ?>
<?php if (empty($recent)): ?>
                <div class="empty-state" style="grid-column:1/-1;"><i class="fas fa-film"></i><h3>No Movies Yet</h3><p>The library is being stocked. Check back soon!</p></div>
<?php endif; ?>
            </div>
        </section>
    </main>

    <?php require_once 'includes/footer.php'; ?>
</body>
</html>
