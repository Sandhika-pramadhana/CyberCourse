<?php

include 'components/connect.php';

if (isset($_COOKIE['user_id'])) {
    $user_id = $_COOKIE['user_id'];
} else {
    $user_id = '';
}

if (isset($_POST['submit'])) {

    $id = create_unique_id();

    
    $name = filter_var($_POST['name'], FILTER_SANITIZE_STRING);
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $message[] = 'Invalid email format!';
    }
    
    $pass = $_POST['pass'];
    $cpass = $_POST['cpass'];
    $hashed_pass = password_hash($pass, PASSWORD_DEFAULT);

    
    if ($pass != $cpass) {
        $message[] = 'Confirm password does not match!';
    } else {

        $select_user = $conn->prepare("SELECT * FROM `users` WHERE email = ?");
        $select_user->execute([$email]);

        if ($select_user->rowCount() > 0) {
            $message[] = 'Email already taken!';
        } else {

            
            if (isset($_FILES['image']) && $_FILES['image']['error'] == 0) {
                $image = $_FILES['image']['name'];
                $ext = pathinfo($image, PATHINFO_EXTENSION);
                $allowed_ext = ['jpg', 'jpeg', 'png', 'gif']; 
                if (!in_array(strtolower($ext), $allowed_ext)) {
                    $message[] = 'Invalid image format! Only JPG, JPEG, PNG, GIF are allowed.';
                } else {
                    $rename = create_unique_id() . '.' . $ext;
                    $image_tmp_name = $_FILES['image']['tmp_name'];
                    $image_folder = 'uploaded_files/' . $rename;

                    move_uploaded_file($image_tmp_name, $image_folder);
                }
            } else {
                $message[] = 'Profile picture is required!';
            }
 
            if (empty($message)) {
                $insert_user = $conn->prepare("INSERT INTO `users`(id, name, email, password, image) VALUES(?,?,?,?,?)");
                $insert_user->execute([$id, $name, $email, $hashed_pass, $rename]);

                
                $verify_user = $conn->prepare("SELECT * FROM `users` WHERE email = ? LIMIT 1");
                $verify_user->execute([$email]);
                $row = $verify_user->fetch(PDO::FETCH_ASSOC);

                if ($verify_user->rowCount() > 0) {
                    setcookie('user_id', $row['id'], time() + 60 * 60 * 24 * 30, '/');
                    header('location:home.php');
                }
            }
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
    <title>Create Account</title>

    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.0/css/all.min.css">
    <link rel="stylesheet" href="css/style.css">
</head>

<body>

    <?php include 'components/user_header.php'; ?>

    <section class="form-container">

        <form class="register" action="" method="post" enctype="multipart/form-data">
            <h3>Create Account</h3>
            <div class="flex">
                <div class="col">
                    <p>Your name <span>*</span></p>
                    <input type="text" name="name" placeholder="Enter your name" maxlength="50" required class="box">
                    <p>Your email <span>*</span></p>
                    <input type="email" name="email" placeholder="Enter your email" maxlength="50" required class="box">
                </div>
                <div class="col">
                    <p>Your password <span>*</span></p>
                    <input type="password" name="pass" placeholder="Enter your password" maxlength="20" required class="box">
                    <p>Confirm password <span>*</span></p>
                    <input type="password" name="cpass" placeholder="Confirm your password" maxlength="20" required class="box">
                </div>
            </div>
            <p>Select Profile Picture <span>*</span></p>
            <input type="file" name="image" accept="image/*" required class="box">
            <p class="link">Already have an account? <a href="login.php">Login Now</a></p>
            <input type="submit" name="submit" value="Register Now" class="btn">
        </form>

    </section>

    <?php include 'components/footer.php'; ?>

    <script src="js/script.js"></script>

</body>

</html>
