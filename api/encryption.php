<?php

function encrypt(String $data) {
    $data = strval($data);

    // Generate an initialization vector (IV)
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
    
    // Encrypt the data using AES-256 in CBC mode
    $encrypted = openssl_encrypt($data, 'aes-256-cbc', getenv("ENCRYPTION_KEY"), 0, $iv);
    
    // Concatenate the IV with the encrypted data
    $result = $iv . $encrypted;
    
    return base64_encode($result); // Encode the result in base64 for storage
}

function decrypt(String $data) {
    // Decode the base64 encoded input
    $data = base64_decode($data);
    
    // Extract the initialization vector (IV) from the input
    $ivLength = openssl_cipher_iv_length('aes-256-cbc');
    $iv = substr($data, 0, $ivLength);
    
    // Extract the encrypted data (excluding the IV)
    $encrypted = substr($data, $ivLength);
    
    // Decrypt the data using AES-256 in CBC mode
    $decrypted = openssl_decrypt($encrypted, 'aes-256-cbc', getenv("ENCRYPTION_KEY"), 0, $iv);
    
    return $decrypted;
}
