<?php

include "dotenv.php";
new DotEnv();

function session($key, $default = NULL){
    return array_key_exists($key, $_SESSION) ? $_SESSION[$key] : $default;
}

function get($key, $default = NULL){
    return array_key_exists($key, $_GET) ? $_GET[$key] : $default;
}

function post($key, $default = NULL) {
    return array_key_exists($key, $_POST) ? $_POST[$key] : $default;
}

$conn = new mysqli(getenv("DB_HOST"), getenv("DB_USER"), getenv("DB_PASS"), getenv("DB_NAME"));

// Function to generate a random token
function generateToken($length = 32) {
    return bin2hex(random_bytes($length));
}

// Function to generate a token expiration time (e.g., 1 hour from now)
function generateExpirationTime() {
    return date('Y-m-d H:i:s', strtotime('+1 hour'));
}

// Function to generate and store a token for a user
function generateAndStoreToken($userId) {
    global $conn;

    $token = generateToken();
    $expiration = generateExpirationTime();

    // Store token in the database
    $stmt = $conn->prepare("INSERT INTO tokens (userID, token, expiration) VALUES (?, ? ,?)");
    $stmt->execute([$userId, $token, $expiration]);

    return $token;
}

// Function to refresh a token
function refreshToken($token) {
    global $conn;

    $expiration = generateExpirationTime();

    // Update token expiration in the database
    $stmt = $conn->prepare("UPDATE tokens SET expiration=? WHERE token=?");
    $stmt->execute([$expiration, $token]);
}

// Function to validate a token
function validateToken($token) {
    global $conn;

    // Check if the token exists and has not expired
    $currentDateTime = date('Y-m-d H:i:s');
    $stmt = $conn->prepare("SELECT * FROM tokens WHERE token=? AND expiration > ?");
    $stmt->execute([$token, $currentDateTime]);
    $stmt->store_result();

    if ($stmt->num_rows() > 0) {
        return true; // Token is valid
    } else {
        return false; // Token is invalid
    }
}

function validateLogin($userName, $password) {
    global $conn;

    //Check if credentials are correct
    $stmt = $conn->prepare("SELECT * FROM users WHERE email=? AND password=?");
    $stmt->execute();
    $result = $stmt->get_result()->fetch_row();

    return $result;
}

?>