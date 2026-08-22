<?php
// Rental management helper functions for MovieHub

if (!defined('SITE_NAME')) require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/functions.php';

class RentalManager {
    private $pdo;
    
    public function __construct($pdo) {
        $this->pdo = $pdo;
    }
    
    // Submit rental request
    public function submit_request($user_id, $movie_id, $start_date, $end_date) {
        try {
            // Check if movie is available
            $stmt = $this->pdo->prepare("SELECT rental_price FROM movies WHERE movie_id = ? AND status = 'available'");
            $stmt->execute([$movie_id]);
            $movie = $stmt->fetch();
            
            if (!$movie) {
                return ['success' => false, 'message' => 'Movie not available for rental'];
            }
            
            // Calculate total amount based on rental days
            $start = new DateTime($start_date);
            $end = new DateTime($end_date);
            $days = $start->diff($end)->days + 1;
            $total_amount = $movie['rental_price'] * $days;
            
            // Insert rental request
            $stmt = $this->pdo->prepare("INSERT INTO rentals (user_id, movie_id, rental_date, due_date, rental_price) VALUES (?, ?, ?, ?, ?)");
            $stmt->execute([$user_id, $movie_id, $start_date, $end_date, $total_amount]);
            
            $rental_id = $this->pdo->lastInsertId();
            log_audit($this->pdo, 'rental_submitted', 'rentals', $rental_id, null, "User {$user_id} submitted rental request {$rental_id} for movie {$movie_id}");
            
            return ['success' => true, 'message' => 'Rental request submitted successfully', 'rental_id' => $rental_id];
            
        } catch (PDOException $e) {
            error_log("Submit rental request error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to submit request. Please try again.'];
        }
    }
    
    // Get user's rental requests
    public function get_user_requests($user_id) {
        try {
            $stmt = $this->pdo->prepare("
                SELECT r.*, m.title, g.name AS genre, m.rental_price AS daily_price
                FROM rentals r 
                JOIN movies m ON r.movie_id = m.movie_id 
                LEFT JOIN genres g ON m.genre_id = g.id
                WHERE r.user_id = ? 
                ORDER BY r.created_at DESC
            ");
            $stmt->execute([$user_id]);
            return $stmt->fetchAll();
        } catch (PDOException $e) {
            error_log("Get user requests error: " . $e->getMessage());
            return [];
        }
    }
    
    // Get all rental requests (admin)
    public function get_all_requests($filters = []) {
        try {
            $where_conditions = [];
            $params = [];
            
            if (isset($filters['status']) && $filters['status']) {
                $where_conditions[] = "r.status = ?";
                $params[] = $filters['status'];
            }
            
            if (isset($filters['search']) && $filters['search']) {
                $where_conditions[] = "(CONCAT(u.first_name, ' ', u.last_name) LIKE ? OR u.email LIKE ? OR m.title LIKE ?)";
                $search_param = "%{$filters['search']}%";
                $params[] = $search_param;
                $params[] = $search_param;
                $params[] = $search_param;
            }
            
            $where_clause = '';
            if (!empty($where_conditions)) {
                $where_clause = 'WHERE ' . implode(' AND ', $where_conditions);
            }
            
            $stmt = $this->pdo->prepare("
                SELECT r.*, u.username, CONCAT(u.first_name, ' ', u.last_name) AS full_name, u.email, u.contact_number, 
                       m.title, g.name AS genre, m.rental_price AS daily_price 
                FROM rentals r 
                JOIN users u ON r.user_id = u.id 
                JOIN movies m ON r.movie_id = m.movie_id 
                LEFT JOIN genres g ON m.genre_id = g.id
                $where_clause
                ORDER BY r.created_at DESC
            ");
            $stmt->execute($params);
            return $stmt->fetchAll();
            
        } catch (PDOException $e) {
            error_log("Get all requests error: " . $e->getMessage());
            return [];
        }
    }
    
    // Get rental request by ID
    public function get_request_by_id($rental_id) {
        try {
            $stmt = $this->pdo->prepare("
                SELECT r.*, u.username, CONCAT(u.first_name, ' ', u.last_name) AS full_name, u.email, u.contact_number, 
                       m.title, g.name AS genre, m.rental_price AS daily_price 
                FROM rentals r 
                JOIN users u ON r.user_id = u.id 
                JOIN movies m ON r.movie_id = m.movie_id 
                LEFT JOIN genres g ON m.genre_id = g.id
                WHERE r.rental_id = ?
            ");
            $stmt->execute([$rental_id]);
            return $stmt->fetch();
        } catch (PDOException $e) {
            error_log("Get request by ID error: " . $e->getMessage());
            return false;
        }
    }
    
    // Approve rental request
    public function approve_request($rental_id, $admin_notes = '') {
        try {
            $stmt = $this->pdo->prepare("UPDATE rentals SET status = 'approved', admin_notes = ? WHERE rental_id = ?");
            $stmt->execute([$admin_notes, $rental_id]);
            $this->pdo->prepare("UPDATE movies m JOIN rentals r ON r.movie_id = m.movie_id SET m.status = 'rented' WHERE r.rental_id = ? AND m.status = 'available'")->execute([$rental_id]);

            log_audit($this->pdo, 'rental_approved', 'rentals', $rental_id, null, "Rental request {$rental_id} approved");
            return ['success' => true, 'message' => 'Rental request approved successfully'];

        } catch (PDOException $e) {
            error_log("Approve request error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to approve request. Please try again.'];
        }
    }

    // Mark an approved rental as returned
    public function mark_returned($rental_id) {
        try {
            $stmt = $this->pdo->prepare("UPDATE rentals SET returned_at = NOW() WHERE rental_id = ? AND status = 'approved' AND returned_at IS NULL");
            $stmt->execute([$rental_id]);
            if ($stmt->rowCount() === 0) {
                return ['success' => false, 'message' => 'Only active approved rentals can be marked as returned.'];
            }
            $this->pdo->prepare("UPDATE movies m JOIN rentals r ON r.movie_id = m.movie_id SET m.status = 'available' WHERE r.rental_id = ?")->execute([$rental_id]);

            log_audit($this->pdo, 'rental_returned', 'rentals', $rental_id, null, "Rental {$rental_id} marked as returned");
            return ['success' => true, 'message' => 'Movie marked as returned.'];
        } catch (PDOException $e) {
            error_log("Mark returned error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to mark rental as returned. Please try again.'];
        }
    }
    
    // Deny rental request
    public function deny_request($rental_id, $admin_notes = '') {
        try {
            $stmt = $this->pdo->prepare("UPDATE rentals SET status = 'denied', admin_notes = ? WHERE rental_id = ?");
            $stmt->execute([$admin_notes, $rental_id]);
            
            log_audit($this->pdo, 'rental_denied', 'rentals', $rental_id, null, "Rental request {$rental_id} denied");
            return ['success' => true, 'message' => 'Rental request denied'];
            
        } catch (PDOException $e) {
            error_log("Deny request error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to deny request. Please try again.'];
        }
    }
    
    // Get rental statistics
    public function get_rental_stats() {
        try {
            $stats = [];
            
            $stmt = $this->pdo->prepare("SELECT COUNT(*) as total FROM rentals");
            $stmt->execute();
            $stats['total'] = $stmt->fetchColumn();
            
            $stmt = $this->pdo->prepare("SELECT COUNT(*) as pending FROM rentals WHERE status = 'pending'");
            $stmt->execute();
            $stats['pending'] = $stmt->fetchColumn();
            
            $stmt = $this->pdo->prepare("SELECT COUNT(*) as approved FROM rentals WHERE status = 'approved'");
            $stmt->execute();
            $stats['approved'] = $stmt->fetchColumn();
            
            $stmt = $this->pdo->prepare("SELECT COUNT(*) as denied FROM rentals WHERE status = 'denied'");
            $stmt->execute();
            $stats['denied'] = $stmt->fetchColumn();
            
            // Calculate total revenue
            $stmt = $this->pdo->prepare("SELECT SUM(rental_price) as revenue FROM rentals WHERE status = 'approved'");
            $stmt->execute();
            $stats['revenue'] = $stmt->fetchColumn() ?? 0;
            
            return $stats;
            
        } catch (PDOException $e) {
            error_log("Get rental stats error: " . $e->getMessage());
            return ['total' => 0, 'pending' => 0, 'approved' => 0, 'denied' => 0, 'revenue' => 0];
        }
    }
    
    // Get pending requests count for user
    public function get_pending_count($user_id) {
        try {
            $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM rentals WHERE user_id = ? AND status = 'pending'");
            $stmt->execute([$user_id]);
            return $stmt->fetchColumn();
        } catch (PDOException $e) {
            error_log("Get pending count error: " . $e->getMessage());
            return 0;
        }
    }
    
    // Check if user has active rental
    public function has_active_rental($user_id) {
        try {
            $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM rentals WHERE user_id = ? AND status = 'approved' AND due_date >= CURDATE()");
            $stmt->execute([$user_id]);
            return $stmt->fetchColumn() > 0;
        } catch (PDOException $e) {
            error_log("Check active rental error: " . $e->getMessage());
            return false;
        }
    }
    
    // Get recent requests (for dashboard)
    public function get_recent_requests($limit = 10) {
        try {
            $stmt = $this->pdo->prepare("
                SELECT r.*, u.username, CONCAT(u.first_name, ' ', u.last_name) AS full_name, u.email, 
                       m.title, g.name AS genre, m.rental_price AS daily_price 
                FROM rentals r 
                JOIN users u ON r.user_id = u.id 
                JOIN movies m ON r.movie_id = m.movie_id 
                LEFT JOIN genres g ON m.genre_id = g.id
                ORDER BY r.created_at DESC 
                LIMIT ?
            ");
            $stmt->execute([(int)$limit]);
            return $stmt->fetchAll();
        } catch (PDOException $e) {
            error_log("Get recent requests error: " . $e->getMessage());
            return [];
        }
    }
}
?>
