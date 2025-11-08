<?php
include "utils.php";

session_start();
ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);
error_reporting(E_ALL);

function errorHandling($errno, $errstr, $errfile, $errline) {
    $errstr = htmlspecialchars($errstr);

    switch ($errno) {
        case E_USER_ERROR:
            http_response_code(500);
            echo json_encode(["Error" => $errstr, "Location" => "line $errline in file $errfile"]);
            exit();
    
        case E_USER_WARNING:
            break;
    
        case E_USER_NOTICE:
            break;
    
        default:
            http_response_code(500);
            echo json_encode(["Error" => $errstr, "Location" => "line $errline in file $errfile"]);
            exit();
    }
    
    /* Don't execute PHP internal error handler */
    return true;
}

set_error_handler("errorHandling");

// Set shutdown handler
register_shutdown_function('api_fatal_error_handler');

function api_fatal_error_handler() {
    $error = error_get_last();

    if ($error && error_reporting() && $error['type'] === E_ERROR) {
        http_response_code(500);
        echo json_encode(["Error" => $error["message"], "Location" => "line ".$error['line']." in file ".$error['file']]);
        exit();
    }
}

header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: OPTIONS,GET,POST,PUT,DELETE");
header("Access-Control-Max-Age: 3600");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

function getClientIP() {
    // Check for shared Internet IP address
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        return $_SERVER['HTTP_CLIENT_IP'];
    }
    // Check for client IP address passed from a proxy
    elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        return $_SERVER['HTTP_X_FORWARDED_FOR'];
    }
    // Return remote address (most reliable)
    else {
        return $_SERVER['REMOTE_ADDR'];
    }
}

$endpoint = get("action");

$clientIP = getClientIP();

$headers = getallheaders();
setReceivedHeaders($headers);

$data = json_decode(file_get_contents('php://input'), true);
setData($data);

$allowedEndpoints = [
    "login" => [
        "allowedMethods" => ["POST"],
        "authRequired" => false,
        "rateLimits" => ["maxRequests" => 5, "timeWindow" => 600]
    ],
    "validateToken" => [
        "allowedMethods" => ["POST"],
        "authRequired" => true,
        "rateLimits" => ["maxRequests" => 5, "timeWindow" => 60]
    ],
    "createAccount" => [
        "allowedMethods" => ["POST"],
        "authRequired" => false,
        "rateLimits" => ["maxRequests" => 5, "timeWindow" => 3600]
    ],
    "verifyAccount" => [
        "allowedMethods" => ["POST"],
        "authRequired" => false,
        "rateLimits" => ["maxRequests" => 15, "timeWindow" => 3600]
    ],
    "deleteAccount" => [
        "allowedMethods" => ["DELETE"],
        "authRequired" => true,
        "rateLimits" => ["maxRequests" => 5, "timeWindow" => 3600]
    ],
    "initiatePasswordReset" => [
        "allowedMethods" => ["POST"],
        "authRequired" => false,
        "rateLimits" => ["maxRequests" => 10, "timeWindow" => 3600]
    ],
    "validatePasswordReset" => [
        "allowedMethods" => ["POST"],
        "authRequired" => false,
        "rateLimits" => ["maxRequests" => 15, "timeWindow" => 3600]
    ],
    "doPasswordReset" => [
        "allowedMethods" => ["PUT"],
        "authRequired" => false,
        "rateLimits" => ["maxRequests" => 15, "timeWindow" => 3600]
    ],
    "updateUserVocabStats" => [
        "allowedMethods" => ["POST"],
        "authRequired" => true,
        "rateLimits" => ["maxRequests" => 10, "timeWindow" => 60]
    ],
    "revokeAllTokens" => [
        "allowedMethods" => ["POST"],
        "authRequired" => true,
        "rateLimits" => ["maxRequests" => 10, "timeWindow" => 600]
    ],
    "logout" => [
        "allowedMethods" => ["POST"],
        "authRequired" => true,
        "rateLimits" => ["maxRequests" => 10, "timeWindow" => 600]
    ],
    "updatePreferences" => [
        "allowedMethods" => ["PUT"],
        "authRequired" => true,
        "rateLimits" => ["maxRequests" => 10, "timeWindow" => 60]
    ],
    "getPreferences" => [
        "allowedMethods" => ["GET"],
        "authRequired" => true,
        "rateLimits" => ["maxRequests" => 10, "timeWindow" => 60]
    ],
];

// Function to get rate limit key for the given endpoint and client
function getRateLimitKey($endpoint, $clientIP) {
    return "rate_limit:$endpoint:$clientIP";
}

// Check rate limits for the given endpoint and client
function checkRateLimit($endpoint, $clientIP) {
    global $allowedEndpoints;

    // Get rate limit parameters for the endpoint
    $maxRequests = $allowedEndpoints[$endpoint]["rateLimits"]["maxRequests"];
    $timeWindow = $allowedEndpoints[$endpoint]["rateLimits"]["timeWindow"];

    // Get or initialize rate limit data for the endpoint and client
    $rateLimitKey = getRateLimitKey($endpoint, $clientIP);
    if (!isset($_SESSION[$rateLimitKey])) {
        $_SESSION[$rateLimitKey] = [
            'requests' => 0,
            'timestamp' => time()
        ];
    }
    $rateLimitData = $_SESSION[$rateLimitKey];

    // Check if the time window has elapsed
    if (time() - $rateLimitData['timestamp'] > $timeWindow) {
        $rateLimitData['requests'] = 0;
        $rateLimitData['timestamp'] = time();
    }

    // Check if the client has exceeded the rate limit for the endpoint
    if ($rateLimitData['requests'] >= $maxRequests) {
        return false; // Rate limit exceeded
    }

    // Increment the request count
    $rateLimitData['requests']++;
    $_SESSION[$rateLimitKey] = $rateLimitData;

    return true; // Rate limit not exceeded
}

if (array_key_exists($endpoint, $allowedEndpoints)) {
    if (in_array($_SERVER["REQUEST_METHOD"],  $allowedEndpoints[$endpoint]["allowedMethods"])) {
        if ($allowedEndpoints[$endpoint]["authRequired"] && getReceivedHeaders("Auth") == null) {
            http_response_code(401);
            echo json_encode(["Error" => "Unauthorized"]);
            exit();
        } elseif (!checkRateLimit($endpoint, $clientIP)) {
            http_response_code(429);
            echo json_encode(["Error" => "Rate limit exceeded for endpoint '$endpoint'"]);
            exit();
        } else {

            if ($endpoint == "login") {
                $email = getData("email");
                $password = getData("password");

                if ($email == null || $password == null) {
                    http_response_code(400);
                    echo json_encode(["Error" => "Missing information"]);
                    exit();
                } else {
                    $userData = validateLogin($email, $password);
                    if ($userData == null) {
                        http_response_code(401);
                        echo json_encode(["Error" => "Invalid login credentials"]);
                        exit();
                    } else {
                        $verified = userIsVerified($userData[0]);
                        echo json_encode([
                            "Error" => "", 
                            "verified" => $verified,
                            "token" => ($verified)?generateAndStoreToken($userData[0]):"",
                            "userData" => [
                                "userID" => $userData[0],
                                "firstName" => decrypt($userData[1]),
                                "lastName" => decrypt($userData[2]),
                                "email" => decrypt($userData[3]),
                                "modePreference" => $userData[6],
                                "class" => $userData[7],
                            ]
                        ]);
                    }
                }
            }

            if ($endpoint == "validateToken") {
                $token = $headers["Auth"];
                echo json_encode(["Error" => "", "TokenValid" => validateToken($token)]);
            }

            if ($endpoint == "createAccount") {
                $firstName = getData("firstName");
                $lastName = getData("lastName");
                $email = getData("email");
                $password = getData("password");
                $modePreference = intval(getData("modePreference"));
                $class = getData("class");

                if (in_array(null, [$firstName, $lastName, $email, $password, $modePreference, $class])) {
                    http_response_code(400);
                    echo json_encode(["Error" => "Missing information"]);
                    exit();
                } else {
                    if (accountExists($email)) {
                        http_response_code(400);
                        echo json_encode(["Error" => "Account with email already exists"]);
                        exit();
                    } else {
                        try {
                            if (createAccount($firstName, $lastName, $password, $email, $modePreference, $class)) {
                                echo json_encode(["Error" => ""]);
                            } else {
                                http_response_code(400);
                                echo json_encode(["Error" => "Invalid email"]);
                                exit();
                            }
                        } catch (Exception $e) {
                            http_response_code(500);
                            echo json_encode(["Error" => $e->getMessage()]);
                            exit();
                        }
                    }
                }
            }

            if ($endpoint == "verifyAccount") {
                $email = getData("email");
                $code = getData("code");
                if ($code == null || $email == null) {
                    http_response_code(400);
                    echo json_encode(["Error" => "Missing information"]);
                    exit();
                } else {
                    $userID = getUserID($email);
                    $success = verifyCode($userID, $code);
                    if ($success) {
                        echo json_encode(["Error" => "", "token" => generateAndStoreToken($userID)]);
                    } else {
                        http_response_code(401);
                        echo json_encode(["Error" => "Code and email not matching"]);
                        exit();
                    }
                }
            }

            if ($endpoint == "initiatePasswordReset") {
                $email = getData('email');
                if ($email == null) {
                    http_response_code(400);
                    echo json_encode(["Error" => "Missing information"]);
                    exit();
                } else {
                    if (accountExists($email)) {
                        initiatePasswordReset($email);
                    }
                    echo json_encode(["Error" => ""]);
                }
            }

            if ($endpoint == "validatePasswordReset") {
                $email = getData("email");
                $code = getData("code");
                if ($email == null || $code == null) {
                    http_response_code(400);
                    echo json_encode(["Error" => "Missing information"]);
                    exit();
                } else {
                    if (validatePasswordReset($email, $code)) {
                        echo json_encode(["Error" => ""]);
                    } else {
                        http_response_code(401);
                        echo json_encode(["Error" => "Unauthorized"]);
                        exit();
                    }
                }
            }

            if ($endpoint == "doPasswordReset") {
                $email = getData("email");
                $code = getData("code");
                $newPassword = getData("newPassword");
                if ($email == null || $code == null || $newPassword == null) {
                    http_response_code(400);
                    echo json_encode(["Error" => "Missing information"]);
                    exit();
                } else {
                    if (validatePasswordReset($email, $code)) {
                        setPassword($email, $newPassword);
                        echo json_encode(["Error" => ""]);
                    } else {
                        http_response_code(401);
                        echo json_encode(["Error" => "Unauthorized"]);
                        exit();
                    }
                }
            }

            if ($endpoint == "deleteAccount") {
                $token = $headers["Auth"];
                $password = getData("password");

                if ($password == null) {
                    http_response_code(400);
                    echo json_encode(["Error" => "Missing information"]);
                    exit();
                } else {
                    if (allowSudo($token, $password)) {
                        deleteAccount(resolveToken($token));
                        echo json_encode(["Error" => ""]);
                    } else {
                        http_response_code(401);
                        echo json_encode(["Error" => "Invalid login credentials"]);
                        exit();
                    }
                }
            }

            if ($endpoint == "updateUserVocabStats") {
                $token = $headers["Auth"];
                $updateWords = getData("statUpdates");

                if ($updateWords == null) {
                    http_response_code(400);
                    echo json_encode(["Error" => "Missing information"]);
                    exit();
                } else {
                    if (validateToken($token)) {
                        $userID = resolveToken($token);
                        foreach ($updateWords as $word => $update) {
                            updateWordStats($userID, $word, $update["fails"], $update["success"]);
                        }
                        echo json_encode(["Error" => ""]);
                    } else {
                        http_response_code(401);
                        echo json_encode(["Error" => "Invalid token"]);
                        exit();
                    }
                }
            }

            if ($endpoint == "revokeAllTokens") {
                $token = $headers["Auth"];
                if (validateToken($token)) {
                    revokeAllTokens(resolveToken($token));
                    echo json_encode(["Error" => ""]);
                } else {
                    http_response_code(401);
                    echo json_encode(["Error" => "Invalid token"]);
                    exit();
                }
            }

            if ($endpoint == "logout") {
                $token = $headers["Auth"];
                if (validateToken($token)) {
                    revokeToken($token);
                    echo json_encode(["Error" => ""]);
                } else {
                    http_response_code(401);
                    echo json_encode(["Error" => "Invalid token"]);
                    exit();
                }
            }

            if ($endpoint == "updatePreferences") {
                $token = $headers["Auth"];
                if (validateToken($token)) {
                    $mode = getData("mode");
                    $class = getData("class");
                    if ($mode != null) {
                        updateModePreference(resolveToken($token), $mode);
                    }
                    if ($class != null) {
                        updateClass(resolveToken($token), $class);
                    }
                    echo json_encode(["Error" => ""]);
                } else {
                    http_response_code(401);
                    echo json_encode(["Error" => "Invalid token"]);
                    exit();
                }
            }

            if ($endpoint == "getPreferences") {
                $token = $headers["Auth"];
                if (validateToken($token)) {
                    $preferences = getPrefences(resolveToken($token));
                    echo json_encode([
                        "Error" => "", 
                        "modePreference" => $preferences[0],
                        "class" => $preferences[1],
                    ]);
                } else {
                    http_response_code(401);
                    echo json_encode(["Error" => "Invalid token"]);
                    exit();
                }
            }
            
        }
    } else {
        http_response_code(405);
        echo json_encode(["Error" => "Method Not Allowed"]);
        exit();
    }
} else {
    http_response_code(404);
    echo json_encode(["Error" => "Not Found"]);
    exit();
}
