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

function validateLogin($email, $password) {
    global $conn;

    $password = hash("md5", $password);

    //Check if credentials are correct
    $stmt = $conn->prepare("SELECT * FROM users WHERE email=? AND password=?");
    $stmt->execute([$email, $password]);
    $result = $stmt->get_result()->fetch_row();

    return $result;
}

function accountExists($email) {
    global $conn;

    $stmt = $conn->prepare("SELECT * FROM users WHERE email=?");
    $stmt->execute([$email]);
    $stmt->store_result();
    if ($stmt->num_rows == 1) {
        return true;
    } else {
        return false;
    }
}

function createAccount($firstName, $lastName, $password, $email, $modePreference, $class) {
    global $conn;

    $password = hash("md5", $password);

    $stmt = $conn->prepare("INSERT INTO users (firstName, lastName, email, password, modePreference, klasse) VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->execute([$firstName, $lastName, $email, $password, $modePreference, $class]);

    $stmt = $conn->prepare("SELECT userID FROM users WHERE email=?");
    $stmt->execute([$email]);
    $userID = $stmt->get_result()->fetch_column();

    $verifyCode = rand(111111, 999999);
    $currentDateTime = date('Y-m-d H:i:s');
    $stmt = $conn->prepare("INSERT INTO verificationCode VALUES (?, ?, ?)");
    $stmt->execute([$userID, $verifyCode, $currentDateTime]);
}

function getUserID($email) {
    global $conn;

    $stmt = $conn->prepare("SELECT userID FROM users WHERE email=?");
    $stmt->execute([$email]);
    return $stmt->get_result()->fetch_column();
}

function verifyCode($userID, $code) {
    global $conn;

    $stmt = $conn->prepare("SELECT * FROM verificationCode WHERE verificationCode=? AND userID=?");
    $stmt->execute([$code, $userID]);
    $stmt->store_result();
    if ($stmt->num_rows() == 0) {
        return false;
    } else {
        $stmt = $conn->prepare("DELETE FROM verificationCode WHERE verificationCode=? AND userID=?");
        $stmt->execute([$code, $userID]);
        return true;
    }
}

function userIsVerified($userID) {
    global $conn;

    $stmt = $conn->prepare("SELECT * FROM verificationCode WHERE userID=?");
    $stmt->execute([$userID]);
    $stmt->store_result();
    if ($stmt->num_rows() == 0) {
        return true;
    } else {
        return false;
    }
}

function resolveToken($token) {
    global $conn;

    $stmt = $conn->prepare("SELECT userID FROM tokens WHERE token=?");
    $stmt->execute([$token]);

    return $stmt->get_result()->fetch_column();
}

function allowSudo($token, $password) {
    global $conn;

    $stmt = $conn->prepare("SELECT firstName FROM users WHERE userID=? AND password=?");
    $stmt->execute([resolveToken($token), hash("md5", $password)]);
    $stmt->store_result();

    if ($stmt->num_rows() == 0) {
        return false;
    } else {
        return true;
    }
}

function deleteAccount($userID) {
    global $conn;

    $stmt = $conn->prepare("DELETE FROM userVocabStats WHERE userID=?");
    $stmt->execute([$userID]);

    $stmt = $conn->prepare("DELETE FROM verificationCode WHERE userID=?");
    $stmt->execute([$userID]);

    $stmt = $conn->prepare("SELECT cLessonID FROM customLessons WHERE userID=?");
    $stmt->execute([$userID]);
    $cLessons = $stmt->get_result()->fetch_all();
    foreach ($cLessons as $cL) {
        $stmt = $conn->prepare("DELETE FROM customLessonVocabs WHERE cLessonID=?");
        $stmt->execute($cL);
    }
    $stmt = $conn->prepare("DELETE FROM customLessons WHERE userID=?");
    $stmt->execute([$userID]);

    $stmt = $conn->prepare("DELETE FROM tokens WHERE userID=?");
    $stmt->execute([$userID]);

    $stmt = $conn->prepare("DELETE FROM users WHERE userID=?");
    $stmt->execute([$userID]);
}

?>