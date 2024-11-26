<?php
include 'components/connect.php';

if(isset($_COOKIE['user_id'])){
   $user_id = $_COOKIE['user_id'];
}else{
   $user_id = '';
}

if(isset($_POST['submit'])){
   $email = $_POST['email'];
   $email = filter_var($email, FILTER_SANITIZE_STRING);
   $pass = sha1($_POST['pass']);
   $pass = filter_var($pass, FILTER_SANITIZE_STRING);

   $max_attempts = 3;
   $time_frame = 15 * 60; 
   $current_time = time();

   $check_attempts = $conn->prepare("SELECT COUNT(*) FROM login_attempts WHERE email = ? AND attempt_time > NOW() - INTERVAL 15 MINUTE");
   $check_attempts->execute([$email]);
   $attempts = $check_attempts->fetchColumn();

   if ($attempts >= $max_attempts) {
       $message[] = 'Too many login attempts. Please try again later.';
   } else {

       $select_user = $conn->prepare("SELECT * FROM users WHERE email = ? AND password = ? LIMIT 1");
       $select_user->execute([$email, $pass]);
       $row = $select_user->fetch(PDO::FETCH_ASSOC);

       if($select_user->rowCount() > 0){
           setcookie('user_id', $row['id'], time() + 60*60*24*30, '/');
           header('location:home.php');
       } else {
           $message[] = 'Incorrect email or password!';

           $insert_attempt = $conn->prepare("INSERT INTO login_attempts (email) VALUES (?)");
           $insert_attempt->execute([$email]);
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


<script src="js/script.js"></script>
   
</body>
</html>