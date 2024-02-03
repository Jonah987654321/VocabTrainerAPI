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
        "authRequired" => true
    ],
    "refreshToken" => [
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
                    echo json_encode(["Error" => "Missing login credentials"]);
                    exit();
                } else {
                    $userData = validateLogin($email, hash("md5", $password));
                    if ($userData == null) {
                        http_response_code(401);
                        echo json_encode(["Error" => "Invalid login credentials"]);
                        exit();
                    } else {
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