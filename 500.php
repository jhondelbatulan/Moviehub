<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>500 - Server Error | MovieHub</title>
    <link rel="stylesheet" href="assets/css/style.css">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="logo">
                <i class="fas fa-film"></i>
                <h1>MovieHub</h1>
            </div>
        </header>

        <main class="main-content">
            <div class="card" style="text-align: center; padding: 3rem;">
                <div style="font-size: 6rem; color: #dc3545; margin-bottom: 1rem;">
                    <i class="fas fa-exclamation-circle"></i>
                </div>
                <h1 style="color: #333; margin-bottom: 1rem;">500 - Server Error</h1>
                <p style="color: #666; margin-bottom: 2rem; font-size: 1.1rem;">
                    Something went wrong on our end. Please try again later.
                </p>
                <div style="display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap;">
                    <a href="index.php" class="btn btn-primary">
                        <i class="fas fa-home"></i>
                        Go Home
                    </a>
                    <button onclick="location.reload()" class="btn btn-secondary">
                        <i class="fas fa-refresh"></i>
                        Try Again
                    </button>
                </div>
            </div>
        </main>
    </div>
</body>
</html>
