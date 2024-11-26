<?php
include 'components/connect.php';

if(isset($_COOKIE['user_id'])){
   $user_id = $_COOKIE['user_id'];
}else{
   $user_id = '';
}

$select_likes = $conn->prepare("SELECT * FROM `likes` WHERE user_id = ?");
$select_likes->execute([$user_id]);
$total_likes = $select_likes->rowCount();

$select_comments = $conn->prepare("SELECT * FROM `comments` WHERE user_id = ?");
$select_comments->execute([$user_id]);
$total_comments = $select_comments->rowCount();

$select_bookmark = $conn->prepare("SELECT * FROM `bookmark` WHERE user_id = ?");
$select_bookmark->execute([$user_id]);
$total_bookmarked = $select_bookmark->rowCount();

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

<section class="quick-select">

   <h1 class="heading">Quick Options</h1>

   <div class="box-container">

      <?php
         if($user_id != ''){
      ?>
      <div class="box">
         <h3 class="title">Likes and Comments</h3>
         <p>Total Likes : <span><?= $total_likes; ?></span></p>
         <a href="likes.php" class="inline-btn">View Likes</a>
         <p>Total Comments : <span><?= $total_comments; ?></span></p>
         <a href="comments.php" class="inline-btn">View Comments</a>
         <p>Saved Playlist : <span><?= $total_bookmarked; ?></span></p>
         <a href="bookmark.php" class="inline-btn">View Bookmark</a>
      </div>
      <?php
         }else{ 
      ?>

      <?php
      }
      ?>

<div class="box">
          <h3 class="title">Top Categories</h3>
          <div class="flex">
            <a href="#"><i class="fas fa-code"></i><span>Development</span></a>
            <a href="#"
              ><i class="fas fa-chart-simple"></i><span>Business</span></a
            >
            <a href="#"><i class="fas fa-pen"></i><span>Design</span></a>
            <a href="#"
              ><i class="fas fa-chart-line"></i><span>Marketing</span></a
            >
            <a href="#"><i class="fas fa-music"></i><span>Music</span></a>
            <a href="#"><i class="fas fa-camera"></i><span>Photograph</span></a>
            <a href="#"><i class="fas fa-cog"></i><span>Software</span></a>
            <a href="#"><i class="fas fa-vial"></i><span>Science</span></a>
          </div>
        </div>

        <div class="box">
          <h3 class="title">Popular Topics</h3>
          <div class="flex">
            <a href="#"
              ><i class="fas fa-wifi"></i><span>Network Pentest</span></a
            >
            <a href="#"
              ><i class="fas fa-mobile"></i><span>Mobile Pentest</span></a
            >
            <a href="#"
              ><i class="fas fa-computer"></i
              ><span>Computer Security Fundamental</span></a
            >
            <a href="#"
              ><i class="fas fa-user-md"></i><span>Computer Forensic</span></a
            >
            <a href="#"
              ><i class="fas fa-balance-scale"></i><span>Cyber Law</span></a
            >
            <a href="#"
              ><i class="fas fa-gears"></i><span>Reverse Engineering</span></a
            >
          </div>
        </div>

        <div class="box tutor">
          <h3 class="title">Become A Teacher</h3>
          <p>
            Lorem ipsum dolor, sit amet consectetur adipisicing elit.
            Perspiciatis, facilis!
          </p>
          <a href="admin/register.php" class="inline-btn">Let's Get Started</a>
        </div>
   </div>
</section>

<section class="courses">
   <h1 class="heading">Latest Courses</h1>
   <div class="box-container">
      <?php
         $select_courses = $conn->prepare("SELECT * FROM `playlist` WHERE status = ? ORDER BY date DESC LIMIT 6");
         $select_courses->execute(['active']);
         if($select_courses->rowCount() > 0){
            while($fetch_course = $select_courses->fetch(PDO::FETCH_ASSOC)){
               $course_id = $fetch_course['id'];

               $select_tutor = $conn->prepare("SELECT * FROM `tutors` WHERE id = ?");
               $select_tutor->execute([$fetch_course['tutor_id']]);
               $fetch_tutor = $select_tutor->fetch(PDO::FETCH_ASSOC);
      ?>
      <div class="box">
         <div class="tutor">
            <img src="uploaded_files/<?= $fetch_tutor['image']; ?>" alt="">
            <div>
               <h3><?= $fetch_tutor['name']; ?></h3>
               <span><?= $fetch_course['date']; ?></span>
            </div>
         </div>
         <img src="uploaded_files/<?= $fetch_course['thumb']; ?>" class="thumb" alt="">
         <h3 class="title"><?= $fetch_course['title']; ?></h3>
         <a href="playlist.php?get_id=<?= $course_id; ?>" class="inline-btn">View Playlist</a>
      </div>
      <?php
         }
      }else{
         echo '<p class="empty">No courses added yet!</p>';
      }
      ?>

   </div>

   <div class="more-btn">
      <a href="courses.php" class="inline-option-btn">View More</a>
   </div>
</section>


<script src="js/script.js"></script>
   
</body>
</html>