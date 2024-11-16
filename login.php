<?php
session_start();
include 'components/connect.php';

if (isset($_COOKIE['user_id'])) {
    $user_id = $_COOKIE['user_id'];
} else {
    $user_id = '';
}

if (isset($_POST['submit'])) {

   
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $pass = $_POST['pass'];

    
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $message[] = 'Invalid email format!';
    } else {
        
        
        if (isset($_SESSION['login_attempts']) && $_SESSION['login_attempts'] >= 5) {
            
            if (isset($_SESSION['last_attempt_time']) && (time() - $_SESSION['last_attempt_time'] < 300)) {
                $message[] = 'Too many failed login attempts.';
            } else {
                unset($_SESSION['login_attempts']);
                unset($_SESSION['last_attempt_time']);
            }
        }

        
        $select_user = $conn->prepare("SELECT * FROM `users` WHERE email = ? LIMIT 1");
        $select_user->execute([$email]);
        $row = $select_user->fetch(PDO::FETCH_ASSOC);

        
        if ($select_user->rowCount() > 0 && password_verify($pass, $row['password'])) {
            unset($_SESSION['login_attempts']);
            unset($_SESSION['last_attempt_time']);
            
            
            setcookie('user_id', $row['id'], time() + 60 * 60 * 24 * 30, '/', '', true, true);
            header('location:home.php');
        } else {
            
            $_SESSION['login_attempts'] = isset($_SESSION['login_attempts']) ? $_SESSION['login_attempts'] + 1 : 1;
            $_SESSION['last_attempt_time'] = time();
            $message[] = 'Incorrect email or password!';
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Home</title>

    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.0/css/all.min.css">
    <link rel="stylesheet" href="css/style.css">
</head>

<body>

    <?php include 'components/user_header.php'; ?>

    <section class="form-container">
        <form action="" method="post" enctype="multipart/form-data" class="login">
            <h3>Welcome!</h3>
            <p>Your email <span>*</span></p>
            <input type="email" name="email" placeholder="Enter your email" maxlength="50" required class="box">
            <p>Your Password <span>*</span></p>
            <input type="password" name="pass" placeholder="Enter your password" maxlength="20" required class="box">
            <p class="link">Don't have an account? <a href="register.php">Register Now!</a></p>
            <input type="submit" name="submit" value="Login Now" class="btn">
        </form>
    </section>

    <?php include 'components/footer.php'; ?>

    <script src="js/script.js"></script>

</body>

</html>
