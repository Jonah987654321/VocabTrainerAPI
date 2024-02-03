<?php
include "utils.php";

header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: OPTIONS,GET,POST,PUT,DELETE");
header("Access-Control-Max-Age: 3600");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

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
                                    "firstName" => $userData[1],
                                    "lastName" => $userData[2],
                                    "email" => $userData[3],
                                    "modePreference" => $userData[5],
                                    "class" => $userData[6],
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

                if (in_array(null, [$firstName, $lastName, $email, $password, $modePreference])) {
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