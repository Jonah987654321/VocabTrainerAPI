<?php
// Include PHPMailer files
require "PHPMailer/src/PHPMailer.php";
require "PHPMailer/src/SMTP.php";
require "PHPMailer/src/Exception.php";

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

function sendMail($email, $subject, $content) {
    // Create a new PHPMailer instance
    $mail = new PHPMailer();

    // Set mailer to use SMTP
    $mail->isSMTP();

    // SMTP host
    $mail->Host = 'smtp.ionos.de';

    // SMTP authentication
    $mail->SMTPAuth = true;

    // SMTP username and password
    $mail->Username = 'noreply@vt.jo-dev.net';
    $mail->Password = getenv("EMAIL_PASSWORD");

    // Enable TLS encryption
    $mail->SMTPSecure = 'tls';

    // TCP port to connect to
    $mail->Port = 587;

    // Set email parameters
    $mail->setFrom('noreply@vt.jo-dev.net', 'VokabelTrainer');
    $mail->addAddress($email); // Add a recipient
    $mail->isHTML(true); // Set email format to HTML

    $mail->Subject = $subject; // Email subject
    $mail->Body = $content;

    // Send the email
    if ($mail->send()) {
        return true; // Email sent successfully
    } else {
        return false; // Email not sent
    }
}

function sendVerificationCode($email, $code) {
    $content = '<html>
        <head>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f2f2f2;
                    padding: 20px;
                }
                .container {
                    max-width: 600px;
                    margin: 0 auto;
                    background-color: #ffffff;
                    border-radius: 10px;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                    padding: 30px;
                }
                h2 {
                    color: #333333;
                }
                p {
                    color: #666666;
                }
                .verification-code {
                    font-size: 24px;
                    color: #007bff;
                    margin-top: 20px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h2>Verifizierungscode</h2>
                <p>Dein Code zur Account-Verifizierung lautet:</p>
                <p class="verification-code">' . $code . '</p>
            </div>
        </body>
        </html>
    ';
    return sendMail($email, 'Dein VokabelTrainer Verification Code', $content);
}

function sendResetCode($email, $code) {
    $content = '<html>
        <head>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f2f2f2;
                    padding: 20px;
                }
                .container {
                    max-width: 600px;
                    margin: 0 auto;
                    background-color: #ffffff;
                    border-radius: 10px;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                    padding: 30px;
                }
                h2 {
                    color: #333333;
                }
                p {
                    color: #666666;
                }
                .verification-code {
                    font-size: 24px;
                    color: #007bff;
                    margin-top: 20px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h2>Passwort zurücksetzen:</h2>
                <p>Dein Code zum Zurücksetzen deines Passwortes lautet:</p>
                <p class="verification-code">' . $code . '</p>
            </div>
        </body>
        </html>
    ';
    return sendMail($email, 'Passwort vom Vokabeltrainer zurücksetzen', $content);
}

?>
