<?php
session_start();
header('Content-Type: application/json');

if (!isset($_SESSION['token_name']) || !isset($_SESSION['token_value'])) {
    $_SESSION['token_name'] = 'field_' . rand(10000, 99999);
    $_SESSION['token_value'] = bin2hex(random_bytes(16));
    $_SESSION['token_created'] = time();
}

echo json_encode([
    'name' => $_SESSION['token_name'],
    'value' => $_SESSION['token_value']
]);
