<?php
include '../components/connect.php';

if(isset($_POST['submit'])){

   $email = $_POST['email'];
   $email = filter_var($email, FILTER_SANITIZE_STRING);
   $pass = sha1($_POST['pass']);
   $pass = filter_var($pass, FILTER_SANITIZE_STRING);

   $max_attempts = 2;
   $time_frame = 15 * 60; 
   $current_time = time();

   $check_attempts = $conn->prepare("SELECT COUNT(*) FROM login_attempts WHERE email = ? AND attempt_time > NOW() - INTERVAL 15 MINUTE");
   $check_attempts->execute([$email]);
   $attempts = $check_attempts->fetchColumn();

   if ($attempts >= $max_attempts) {
       $message[] = 'Too many login attempts. Please try again later.';
   } else {
       
       $select_admin = $conn->prepare("SELECT * FROM `tutors` WHERE email = ? AND password = ? LIMIT 1");
       $select_admin->execute([$email, $pass]);
       $row = $select_admin->fetch(PDO::FETCH_ASSOC);

       if($select_admin->rowCount() > 0){
           setcookie('tutor_id', $row['id'], time() + 60*60*24*30, '/');
           header('location:dashboard.php');
       } else {
           $message[] = 'Email atau password salah!';

           
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
   <title>Login</title>

   <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.0/css/all.min.css">
   <link rel="stylesheet" href="../css/admin_style.css">
</head>
<body style="padding-left: 0;">

<?php
if(isset($message)){
   foreach($message as $message){
      echo '
      <div class="message form">
         <span>'.$message.'</span>
         <i class="fas fa-times" onclick="this.parentElement.remove();"></i>
      </div>
      ';
   }
}
?>

<section class="form-container">
   <form action="" method="post" enctype="multipart/form-data" class="login">
      <h3>Welcome back!</h3>
      <p>Your email <span>*</span></p>
      <input type="email" name="email" placeholder="Enter your email" maxlength="20" required class="box">
      <p>Your password <span>*</span></p>
      <input type="password" name="pass" placeholder="Enter your password" maxlength="20" required class="box">
      <p class="link">Don't have an account? <a href="register.php">Register New</a></p>
      <input type="submit" name="submit" value="Login Now" class="btn">
   </form>
</section>

<script>
let darkMode = localStorage.getItem('dark-mode');
let body = document.body;

const enabelDarkMode = () =>{
   body.classList.add('dark');
   localStorage.setItem('dark-mode', 'enabled');
}

const disableDarkMode = () =>{
   body.classList.remove('dark');
   localStorage.setItem('dark-mode', 'disabled');
}

if(darkMode === 'enabled'){
   enabelDarkMode();
}else{
   disableDarkMode();
}
</script>

</body>
</html>
