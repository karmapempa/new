<?php
session_start();
include 'connect.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (isset($_POST['login'])) {
        $email = $_POST['email'];
        $password = $_POST['password'];

        // Check login credentials
        $sql = "SELECT * FROM management WHERE email = ?";
        $stmt = $conn->prepare($sql);
        
        if ($stmt === false) {
            die('Prepare failed: ' . $conn->error);
        }

        $stmt->bind_param('s', $email);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();

        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            header("Location: dashboard.php"); //dashboard  file  will be  redirected
            exit;
        } else {
            echo "Invalid email or password.";
        }
    } elseif (isset($_POST['signup'])) {
        $name = $_POST['name'];
        $email = $_POST['email'];
        $password = $_POST['password'];
        $confirm_password = $_POST['confirm_password'];

        if ($password !== $confirm_password) {
            echo "Passwords do not match.";
        } else {
            // Hash the password
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);

            // Insert new user
            $sql = "INSERT INTO management (name, email, password) VALUES (?, ?, ?)";
            $stmt = $conn->prepare($sql);

            if ($stmt === false) {
                die('Prepare failed: ' . $conn->error);
            }

            $stmt->bind_param('sss', $name, $email, $hashed_password);
            if ($stmt->execute()) {
                echo "Signup successful!";
            } else {
                echo "Error: " . $stmt->error;
            }
        }
    }
}

$conn->close();
?>
