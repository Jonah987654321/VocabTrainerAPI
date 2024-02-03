<?php

include 'utils.php';

// API Endpoints
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ($_POST['action'] === 'login') {
        // Login endpoint
        $email = $_POST['email'];
        $password = $_POST['password'];

        // Authenticate user (you should implement this part)
        // For demonstration purposes, let's assume authentication is successful and get the user ID
        $userId = 123; // Get the actual user ID from your authentication process

        // Generate and store token
        $token = generateAndStoreToken($userId);

        echo json_encode(['token' => $token]);
    } elseif ($_POST['action'] === 'refresh') {
        // Token refresh endpoint
        $token = $_POST['token'];

        // Refresh token
        refreshToken($token);

        echo json_encode(['message' => 'Token refreshed successfully']);
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'GET') {
    if ($_GET['action'] === 'validate') {
        // Token validation endpoint
        $token = $_GET['token'];

        // Validate token
        $isValid = validateToken($token);

        if ($isValid) {
            echo json_encode(['valid' => true]);
        } else {
            echo json_encode(['valid' => false]);
        }
    }
}
?>
