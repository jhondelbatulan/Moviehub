<?php
// Movie management helper functions for MovieHub

if (!defined('SITE_NAME')) require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/functions.php';

class MovieManager {
    private $pdo;
    
    public function __construct($pdo) {
        $this->pdo = $pdo;
    }
    
    // Get all movies (with genre name)
    public function get_all_movies() {
        try {
            $stmt = $this->pdo->prepare("SELECT m.*, g.name AS genre FROM movies m LEFT JOIN genres g ON m.genre_id = g.id ORDER BY m.title");
            $stmt->execute();
            return $stmt->fetchAll();
        } catch (PDOException $e) {
            error_log("Get movies error: " . $e->getMessage());
            return [];
        }
    }
    
    // Get available movies
    public function get_available_movies() {
        try {
            $stmt = $this->pdo->prepare("SELECT m.*, g.name AS genre FROM movies m LEFT JOIN genres g ON m.genre_id = g.id WHERE m.status = 'available' ORDER BY m.title");
            $stmt->execute();
            return $stmt->fetchAll();
        } catch (PDOException $e) {
            error_log("Get available movies error: " . $e->getMessage());
            return [];
        }
    }
    
    // Get movie by ID
    public function get_movie_by_id($movie_id) {
        try {
            $stmt = $this->pdo->prepare("SELECT m.*, g.name AS genre FROM movies m LEFT JOIN genres g ON m.genre_id = g.id WHERE m.movie_id = ?");
            $stmt->execute([$movie_id]);
            return $stmt->fetch();
        } catch (PDOException $e) {
            error_log("Get movie by ID error: " . $e->getMessage());
            return false;
        }
    }
    
    // Resolve a genre name to its id, creating the genre if it does not exist
    public function get_or_create_genre_id($genre_name) {
        $genre_name = trim($genre_name);
        if ($genre_name === '') return null;
        try {
            $stmt = $this->pdo->prepare("SELECT id FROM genres WHERE name = ?");
            $stmt->execute([$genre_name]);
            $id = $stmt->fetchColumn();
            if ($id) return (int)$id;
            $stmt = $this->pdo->prepare("INSERT INTO genres (name) VALUES (?)");
            $stmt->execute([$genre_name]);
            return (int)$this->pdo->lastInsertId();
        } catch (PDOException $e) {
            error_log("Genre resolve error: " . $e->getMessage());
            return null;
        }
    }
    
    // Add new movie
    public function add_movie($data) {
        try {
            $stmt = $this->pdo->prepare("INSERT INTO movies (title, description, genre_id, release_year, director, cast_members, duration_minutes, rating, rental_price, poster, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([
                $data['title'],
                $data['description'] ?? '',
                $data['genre_id'] ?? null,
                !empty($data['release_year']) ? (int)$data['release_year'] : null,
                $data['director'] ?? null,
                $data['cast_members'] ?? null,
                !empty($data['duration_minutes']) ? (int)$data['duration_minutes'] : null,
                isset($data['rating']) && $data['rating'] !== '' ? (float)$data['rating'] : null,
                $data['rental_price'],
                $data['poster'] ?? null,
                $data['status'] ?? 'available'
            ]);
            
            $movie_id = $this->pdo->lastInsertId();
            log_audit($this->pdo, 'movie_added', 'movies', $movie_id, $data['title'], "Movie '{$data['title']}' added with ID {$movie_id}");
            return ['success' => true, 'message' => 'Movie added successfully', 'movie_id' => $movie_id];
            
        } catch (PDOException $e) {
            error_log("Add movie error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to add movie. Please try again.'];
        }
    }
    
    // Update movie
    public function update_movie($movie_id, $data) {
        try {
            $stmt = $this->pdo->prepare("UPDATE movies SET title = ?, description = ?, genre_id = ?, release_year = ?, director = ?, cast_members = ?, duration_minutes = ?, rating = ?, rental_price = ?, poster = ?, status = ? WHERE movie_id = ?");
            $stmt->execute([
                $data['title'],
                $data['description'] ?? '',
                $data['genre_id'] ?? null,
                !empty($data['release_year']) ? (int)$data['release_year'] : null,
                $data['director'] ?? null,
                $data['cast_members'] ?? null,
                !empty($data['duration_minutes']) ? (int)$data['duration_minutes'] : null,
                isset($data['rating']) && $data['rating'] !== '' ? (float)$data['rating'] : null,
                $data['rental_price'],
                $data['poster'] ?? null,
                $data['status'] ?? 'available',
                $movie_id
            ]);
            
            log_audit($this->pdo, 'movie_updated', 'movies', $movie_id, $data['title'], "Movie ID {$movie_id} updated");
            return ['success' => true, 'message' => 'Movie updated successfully'];
            
        } catch (PDOException $e) {
            error_log("Update movie error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to update movie. Please try again.'];
        }
    }
    
    // Delete movie
    public function delete_movie($movie_id) {
        try {
            // Check if movie has pending rentals
            $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM rentals WHERE movie_id = ? AND status = 'pending'");
            $stmt->execute([$movie_id]);
            $pending_requests = $stmt->fetchColumn();
            
            if ($pending_requests > 0) {
                return ['success' => false, 'message' => 'Cannot delete movie with pending rental requests'];
            }
            
            // Get movie title for logging
            $movie = $this->get_movie_by_id($movie_id);
            $title = $movie ? $movie['title'] : 'Unknown';
            
            $stmt = $this->pdo->prepare("DELETE FROM movies WHERE movie_id = ?");
            $stmt->execute([$movie_id]);
            
            log_audit($this->pdo, 'movie_deleted', 'movies', $movie_id, $title, "Movie '{$title}' (ID: {$movie_id}) deleted");
            return ['success' => true, 'message' => 'Movie deleted successfully'];
            
        } catch (PDOException $e) {
            error_log("Delete movie error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to delete movie. Please try again.'];
        }
    }
    
    // Get movie statistics
    public function get_movie_stats() {
        try {
            $stats = [];
            
            $stmt = $this->pdo->prepare("SELECT COUNT(*) as total FROM movies");
            $stmt->execute();
            $stats['total'] = $stmt->fetchColumn();
            
            $stmt = $this->pdo->prepare("SELECT COUNT(*) as available FROM movies WHERE status = 'available'");
            $stmt->execute();
            $stats['available'] = $stmt->fetchColumn();
            
            $stmt = $this->pdo->prepare("SELECT COUNT(*) as rented FROM movies WHERE status = 'rented'");
            $stmt->execute();
            $stats['rented'] = $stmt->fetchColumn();
            
            $stmt = $this->pdo->prepare("SELECT COUNT(*) as maintenance FROM movies WHERE status = 'maintenance'");
            $stmt->execute();
            $stats['maintenance'] = $stmt->fetchColumn();
            
            return $stats;
            
        } catch (PDOException $e) {
            error_log("Get movie stats error: " . $e->getMessage());
            return ['total' => 0, 'available' => 0, 'rented' => 0, 'maintenance' => 0];
        }
    }
    
    // Search movies
    public function search_movies($query) {
        try {
            $stmt = $this->pdo->prepare("SELECT m.*, g.name AS genre FROM movies m LEFT JOIN genres g ON m.genre_id = g.id WHERE m.title LIKE ? OR m.director LIKE ? OR m.cast_members LIKE ? OR m.description LIKE ? OR g.name LIKE ? ORDER BY m.title");
            $search_term = "%{$query}%";
            $stmt->execute([$search_term, $search_term, $search_term, $search_term, $search_term]);
            return $stmt->fetchAll();
        } catch (PDOException $e) {
            error_log("Search movies error: " . $e->getMessage());
            return [];
        }
    }
    
    // Get movies by genre
    public function get_movies_by_genre($genre_id) {
        try {
            $stmt = $this->pdo->prepare("SELECT m.*, g.name AS genre FROM movies m LEFT JOIN genres g ON m.genre_id = g.id WHERE m.genre_id = ? ORDER BY m.title");
            $stmt->execute([$genre_id]);
            return $stmt->fetchAll();
        } catch (PDOException $e) {
            error_log("Get movies by genre error: " . $e->getMessage());
            return [];
        }
    }
    
    // Get all genres
    public function get_genres() {
        try {
            $stmt = $this->pdo->prepare("SELECT id, name FROM genres ORDER BY name");
            $stmt->execute();
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log("Get genres error: " . $e->getMessage());
            return [];
        }
    }
}
?>
