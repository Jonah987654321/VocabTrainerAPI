<?php

// Include encryption and dotenv files
include "encryption.php";
include "sendVerificationMail.php";
include "dotenv.php";
new DotEnv();

// Function to get a value from the GET request with a default value
function get($key, $default = NULL)
{
    return array_key_exists($key, $_GET) ? $_GET[$key] : $default;
}

// Function and variable to handle received headers
$headers = array();

function setReceivedHeaders($receivedHeaders) {
    global $headers;

    $headers = $receivedHeaders;
}

function getReceivedHeaders($key, $default = NULL) {
    global $headers;
    return array_key_exists($key, $headers) ? $headers[$key] : $default;
}

// Function and variable to handle received data
$data = array();

function setData($receivedData) {
    global $data;

    $data = $receivedData;
}

function getData($key, $default = NULL) {
    global $data;
    return array_key_exists($key, $data) ? $data[$key] : $default;
}

// Connect to the database using environment variables
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

// Function to validate user login
function validateLogin($email, $password) {
    global $conn;

    $email = hash("sha256", $email);

    // Check if credentials are correct
    $stmt = $conn->prepare("SELECT * FROM users WHERE emailCheckHash=?");
    $stmt->execute([$email]);
    $result = $stmt->get_result()->fetch_row();

    if (password_verify($password,  $result[5])) {
        return $result;
    } else {
        return null;
    }
}

// Function to check if an account exists with the given email
function accountExists($email) {
    global $conn;

    $stmt = $conn->prepare("SELECT * FROM users WHERE emailCheckHash=?");
    $stmt->execute([hash("sha256", $email)]);
    $stmt->store_result();
    if ($stmt->num_rows == 1) {
        return true;
    } else {
        return false;
    }
}

// Function to create a new user account
function createAccount($firstName, $lastName, $password, $email, $modePreference, $class) {
    $verifyCode = rand(111111, 999999);
    $currentDateTime = date('Y-m-d H:i:s');
    if(sendVerificationCode($email, $verifyCode)) {
        global $conn;

        $password = password_hash($password, PASSWORD_DEFAULT);

        $stmt = $conn->prepare("INSERT INTO users (firstName, lastName, email, emailCheckHash, password, modePreference, klasse) VALUES (?, ?, ?, ?, ?, ?, ?)");
        $stmt->execute([encrypt($firstName), encrypt($lastName), encrypt($email), hash("sha256", $email), $password, $modePreference, $class]);

        $stmt = $conn->prepare("SELECT userID FROM users WHERE emailCheckHash=?");
        $stmt->execute([hash("sha256", $email)]);
        $userID = $stmt->get_result()->fetch_column();

        $stmt = $conn->prepare("INSERT INTO verificationCode VALUES (?, ?, ?)");
        $stmt->execute([$userID, $verifyCode, $currentDateTime]);
        return true;
    } else {
        return false;
    }
}

// Function to get the user ID by email
function getUserID($email) {
    global $conn;

    $stmt = $conn->prepare("SELECT userID FROM users WHERE emailCheckHash=?");
    $stmt->execute([hash("sha256", $email)]);
    return $stmt->get_result()->fetch_column();
}

// Function to verify a user's account using a code
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

// Function to check if a user's account is verified
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

// Function to resolve a token and return the user ID
function resolveToken($token) {
    global $conn;

    $stmt = $conn->prepare("SELECT userID FROM tokens WHERE token=?");
    $stmt->execute([$token]);

    return $stmt->get_result()->fetch_column();
}

// Function to allow sudo access with a token and password
function allowSudo($token, $password) {
    global $conn;

    $stmt = $conn->prepare("SELECT password FROM users WHERE userID=?");
    $stmt->execute([resolveToken($token)]);
    $result = $stmt->get_result()->fetch_column();

    if (password_verify($password, $result)) {
        return true;
    } else {
        return false;
    }
}

// Function to delete a user account
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

// Function to update word stats for a user
function updateWordStats($userID, $vocabID, $newFails, $newSuccess) {
    global $conn;

    $stmt = $conn->prepare("SELECT * FROM userVocabStats WHERE userID=? AND vocabID=?");
    $stmt->execute([$userID, $vocabID]);
    $stmt->store_result();
    if ($stmt->num_rows() == 0) {
        $stmt = $conn->prepare("INSERT INTO userVocabStats (userID, vocabID, failCount, successCount) VALUES (?, ?, ?, ?)");
        $stmt->execute([$userID, $vocabID, $newFails, $newSuccess]);
    } else {
        $stmt = $conn->prepare("SELECT * FROM userVocabStats WHERE userID=? AND vocabID=?");
        $stmt->execute([$userID, $vocabID]);
        $result = $stmt->get_result()->fetch_row();
        $stmt = $conn->prepare("UPDATE userVocabStats SET failCount=?, successCount=? WHERE userID=? AND vocabID=?");
        $stmt->execute([intval($newFails)+intval($result[2]), intval($newSuccess)+intval($result[3]), $userID, $vocabID]);
    }
}

?>