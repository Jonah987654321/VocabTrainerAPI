<?php

include "utils.php";

ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);

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

header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: OPTIONS,GET,POST,PUT,DELETE");
header("Access-Control-Max-Age: 3600");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

$endpoint = get("action");
$headers = getallheaders();

$allowedEndpoints = [
    "login" => [
        "allowedMethods" => ["POST"],
        "authRequired" => false
    ],
    "createAccount" => [
        "allowedMethods" => ["POST"],
        "authRequired" => false
    ],
    "verifyAccount" => [
        "allowedMethods" => ["POST"],
        "authRequired" => false
    ],
    "deleteAccount" => [
        "allowedMethods" => ["POST"],
        "authRequired" => true
    ],
    "createCustomLesson" => [
        "allowedMethods" => ["POST"],
        "authRequired" => true
    ]
];

if (array_key_exists($endpoint, $allowedEndpoints)) {
    if (in_array($_SERVER["REQUEST_METHOD"],  $allowedEndpoints[$endpoint]["allowedMethods"])) {
        if ($allowedEndpoints[$endpoint]["authRequired"] && $headers["Auth"] == null) {
            http_response_code(401);
            echo json_encode(["Error" => "Unauthorized"]);
            exit();
        } else {

            if ($endpoint == "login") {
                $email = post("email");
                $password = post("password");

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
                        if (userIsVerified($userData[0])) {
                            echo json_encode([
                                "Error" => "", 
                                "token" => generateAndStoreToken($userData[0]),
                                "userData" => [
                                    "userID" => $userData[0],
                                    "firstName" => decrypt($userData[1]),
                                    "lastName" => decrypt($userData[2]),
                                    "email" => decrypt($userData[3]),
                                    "modePreference" => decrypt($userData[5]),
                                    "class" => decrypt($userData[6]),
                                ]
                            ]);
                        } else {
                            http_response_code(401);
                            echo json_encode(["Error" => "Account not verified"]);
                            exit();
                        }
                    }
                }
            }

            if ($endpoint == "createAccount") {
                $firstName = post("firstName");
                $lastName = post("lastName");
                $email = post("email");
                $password = post("password");
                $modePreference = post("modePreference");
                $class = post("class");

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
                            createAccount($firstName, $lastName, $password, $email, $modePreference, $class);

                            //Send verification code!!!
                            echo json_encode(["Error" => ""]);
                        } catch (Exception $e) {
                            echo json_encode(["Error" => $e->getMessage()]);
                        }
                        exit();
                    }
                }
            }

            if ($endpoint == "verifyAccount") {
                $email = post("email");
                $code = post("code");
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

            if ($endpoint == "deleteAccount") {
                $token = $headers["Auth"];
                $password = post("password");

                if ($password == null || $token == null) {
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

            if ($endpoint == "createCustomLesson") {

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
