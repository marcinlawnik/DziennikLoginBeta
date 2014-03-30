<?php
require 'bcryptWrapper.php';
require 'config.local.php';
//function to check password
function checkPassword($password, $username = false) {
    $length = strlen($password);

    if ($length < 8) {
        return FALSE;
    } elseif ($length > 32) {
        return FALSE;
    } else {

//check for a couple of bad passwords:
        if ($username && strtolower($password) == strtolower($username)) {
        return FALSE;
        } elseif (strtolower($password) == 'password') {
        return FALSE;
        } else {

            preg_match_all("/(.)\1{2}/", $password, $matches);
            $consecutives = count($matches[0]);

            preg_match_all("/\d/i", $password, $matches);
            $numbers = count($matches[0]);

            preg_match_all("/[A-Z]/", $password, $matches);
            $uppers = count($matches[0]);

            preg_match_all("/[^A-z0-9]/", $password, $matches);
            $others = count($matches[0]);

//see if there are 3 consecutive chars (or more) and fail!
            if ($consecutives > 0) {
        return FALSE;
            } elseif ($others > 1 || ($uppers > 1 && $numbers > 1)) {
//bulletproof
        return TRUE;
            } elseif (($uppers > 0 && $numbers > 0) || $length > 14) {
//very strong
        return TRUE;
            } else if ($uppers > 0 || $numbers > 2 || $length > 9) {
//strong
        return TRUE;
            } else if ($numbers > 1) {
//fair
        return FALSE;
            } else {
//weak
        return FALSE;
            }
        }
    }
    return $returns;
}
$db_host = $CONF['databaseHost'];
$db_name = $CONF['databaseName'];
$db_username = $CONF['databaseUsername'];
$db_password = $CONF['databasePassword'];


if (isset($_POST['isSent']) && $_POST['isSent'] == 'yes') {//check if form has been sent
    $registrationErrors = '';
    //begin checks
    //username
    if (preg_match('/^[A-Za-z][A-Za-z0-9]{7,31}$/', $_POST['username'])) {//check username
        $usernameOkay = TRUE;
    } else {
        $usernameOkay = FALSE;
        $registrationErrors .= "Nieprawidłowa nazwa użytkownika!<br>";
    }

    //email
    if (filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
        $emailOkay = TRUE;
    } else {
        $emailOkay = FALSE;
        $registrationErrors .= "Nieprawidłowy adres e-mail!<br>";
    }
    //passwords
    if ($_POST['password'] != '' && $_POST['passwordConfirm'] != '') {//if passwords are empty
        if ($_POST['password'] === $_POST['passwordConfirm']) {//passwords match
            $passwordOkay = TRUE;
            if (checkPassword($_POST['password'], $_POST['username'])) {//password final check
                $passwordOkay = TRUE;
            } else {
                $passwordOkay = FALSE;
                $registrationErrors .= "Hasło nie spełnia wymagań!<br>";
            }
        } else {
            $passwordOkay = FALSE;
            $registrationErrors .= "Hasła nie zgadzają się!<br>";
        }
    } else {
        $passwordOkay = FALSE;
        $registrationErrors .= "Hasła są puste!<br>";
    }

    //register username
    if ($_POST['registerUsername'] != '') {//if register username is empty
        $registerUsernameOkay = TRUE;
    } else {
        $passwordOkay = FALSE;
        $registrationErrors .= "Nazwa użytkownika Dziennika jest pusta!<br>";
    }

    //register passwords
    if ($_POST['registerPassword'] != '' && $_POST['registerPasswordConfirm'] != '') {//if register passwords are empty
        if ($_POST['registerPassword'] === $_POST['registerPasswordConfirm']) {// register passwords match
            $registerPasswordOkay = TRUE;
        } else {
            $registerPasswordOkay = FALSE;
            $registrationErrors .= "Hasła do Dziennika nie zgadzają się!<br>";
        }
    } else {
        $registerPasswordOkay = FALSE;
        $registrationErrors .= "Hasła do Dziennika są puste!<br>";
    }
    $isSuccessful = 'danger';


    if ($usernameOkay && $passwordOkay && $emailOkay && $registerUsernameOkay && $registerPasswordOkay) {//can write to database && $registerUsernameOkay
        //validated all data, can now insert
        //connect to database
        try {
            $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8", $db_username, $db_password, array(
                PDO::MYSQL_ATTR_INIT_COMMAND => 'SET NAMES utf8'
            ));
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $pdo->beginTransaction();
        } catch (PDOException $e) {
            return 'Błąd bazy danych:' . $e->getMessage();
        }
        //hash password
        $crypter = new Bcrypt(10);  // correct
        $hashedPassword = $crypter->hash($_POST['password']);
        //crypt register password
        $fileContents = file_get_contents('public.key');
        $publicKey = openssl_pkey_get_public($fileContents);
        $registerPasswordEncrypted = '';
        if (!openssl_public_encrypt($_POST['registerPassword'], $registerPasswordEncrypted, $publicKey))
            die('Failed to encrypt data');
        openssl_free_key($publicKey);
        
        //check e-mail
        try {
            //tabela USERS
            $stmt = $pdo->prepare('INSERT INTO users VALUES (NULL,:userName,:userPassword, :userEmail, 1, NULL, NULL, NULL, NULL, 0, NULL, now(), :userRegistrationIp)');
            $stmt->bindParam(':userName', $_POST['username']);
            $stmt->bindParam(':userPassword', $hashedPassword);
            $stmt->bindParam(':userEmail', $_POST['email']);
            $stmt->bindParam(':userRegistrationIp',$_SERVER['REMOTE_ADDR']);
            //$stmt->bindParam(':registerPassword', $registerPasswordEncrypted);
            $stmt->execute();

            $userId = $pdo->lastInsertId('user_id');
            //tabela registerPasswords
            $stmt2 = $pdo->prepare('INSERT INTO registerPasswords VALUES (:userId,:registerUsername,:registerPassword)');
            $stmt2->bindParam(':userId', $userId);
            $stmt2->bindParam(':registerUsername', $_POST['registerUsername']);
            $stmt2->bindParam(':registerPassword', $registerPasswordEncrypted);
            //$stmt->bindParam(':registerPassword', $registerPasswordEncrypted);
            $stmt2->execute();
            
            //tabela reportJobs
            $stmt3 = $pdo->prepare('INSERT INTO reportjobs VALUES (NULL,:userId, \'DAILY\', :userEmail, \'CHILD\', 1)');
            $stmt3->bindParam(':userId', $userId);
            $stmt3->bindParam(':userEmail', $_POST['email']);
            //$stmt->bindParam(':registerPassword', $registerPasswordEncrypted);
            $stmt3->execute();
            $pdo->commit();
            
            $registrationErrors = 'Zarejestrowano poprawnie. Wkrótce otrzymasz pierwszy (DUŻY, ponieważ wyślemy wszystkie aktualne oceny od razu) e-mail z ocenami.';
            $isSuccessful = 'success';
            
        } catch (PDOException $e) {
            $registrationErrors = 'Błąd bazy danych, powiadom administratora: marcin@lawniczak.me i prześlij ten błąd: '.base64_encode($e->getMessage());
            $pdo->rollBack();
        }
    }
}
?>

<!DOCTYPE html>
<html lang="pl">
    <head>
        <meta charset="utf-8">
        <title>DziennikLogin - Rejestracja do bety</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="description" content="">
        <meta name="author" content="">
        <!-- Le styles -->
        <link href="http://netdna.bootstrapcdn.com/bootstrap/3.1.1/css/bootstrap.min.css" rel="stylesheet"  media="screen">
        <style type="text/css">
            body {
                padding-top: 20px;
                padding-bottom: 40px;
            }

            /* Custom container */
            .container-narrow {
                margin: 0 auto;
                max-width: 700px;
            }
            .container-narrow > hr {
                margin: 30px 0;
            }
        </style>
        <link href="../bootstrap/css/bootstrap-responsive.min.css" rel="stylesheet">
    </head>

    <body>
        <div class="container-narrow">


            <div class="masthead">
                <h3 class="text-muted" style=""><img src="logo_small.png" style="margin-right: 20px;"> DziennikLogin</h3>
            </div>

            <hr>
            <div class="container-fluid">
            <form action='joinBeta.php' method="POST" role="form">
                <fieldset>
                    <div id="legend">
                        <legend class="">Rejestracja do bety</legend>
                    </div>
                    <p class="bg-<?php echo $isSuccessful; ?>">
                    <?php if (isSet($registrationErrors)) {
                        echo $registrationErrors;
                    } ?>
                    </p>
                    <div class="form-group">
                        <!-- Username -->
                        <label for="username" class="control-label">Nazwa użytkownika</label>
                        <div>
                            <input class="form-control" type="text" id="username" name="username" placeholder="" value="<?php echo (isset($_POST['username']) ? $_POST['username'] : '');?>" class="input-xlarge">
                            <p class="help-block">Nazwa użytkownika może zawierać małe i wielkie litery oraz cyfry.</p>
                        </div>
                    </div>

                    <div class="form-group">
                        <!-- E-mail -->
                        <label for="email" class="control-label">E-mail</label>
                        <div>
                            <input class="form-control" type="text" id="email" name="email" placeholder="" value="<?php echo (isset($_POST['email']) ? $_POST['email'] : '');?>" class="input-xlarge">
                            <p class="help-block">Podaj swój E-mail (Na niego będą wysyłane oceny).</p>
                        </div>
                    </div>

                    <div class="form-group">
                        <!-- Password-->
                        <label for="password" class="control-label">Hasło</label>
                        <div>
                            <input class="form-control" type="password" id="password" name="password" placeholder="" class="input-xlarge">
                            <p class="help-block">Hasło powinno mieć co najmniej 8 znaków.</p>
                        </div>
                    </div>

                    <div class="form-group">
                        <!-- Password -->
                        <label for="passwordConfirm" class="control-label">Potwierdź Hasło</label>
                        <div>
                            <input class="form-control" type="password" id="passwordConfirm" name="passwordConfirm" placeholder="" class="input-xlarge">
                            <p class="help-block">Proszę potwierdź hasło</p>
                        </div>
                    </div>
                    <div class="form-group">
                        <!-- Username -->
                        <label for="registerUsername" class="control-label">Nazwa użytkownika Dziennika</label>
                        <div>
                            <input class="form-control" type="text" id="registerUsername" name="registerUsername" placeholder="" value="<?php echo (isset($_POST['registerUsername']) ? $_POST['registerUsername'] : '');?>" class="input-xlarge">
                            <p class="help-block">Używana do logowania w Dzienniku Elektronicznym szkoły.</p>
                        </div>
                    </div>
                    <div class="form-group">
                        <!-- Password-->
                        <label for="registerPassword" class="control-label">Hasło do Dziennika</label>
                        <div>
                            <input class="form-control" type="password" id="registerPassword" name="registerPassword" placeholder="" class="input-xlarge">
                            <p class="help-block">Używane do logowania w Dzienniku Elektronicznym szkoły.</p>
                        </div>
                    </div>

                    <div class="form-group">
                        <!-- Password -->
                        <label for="registerPasswordConfirm" class="control-label">Potwierdź Hasło do Dziennika</label>
                        <div>
                            <input class="form-control" type="password" id="registerPasswordConfirm" name="registerPasswordConfirm" placeholder="" class="input-xlarge">
                            <p class="help-block">Proszę potwierdź hasło do logowania w Dzienniku Elektronicznym szkoły.</p>
                        </div>
                    </div>
                    <input type="hidden" id="isSent" name ="isSent" value="yes">
                    <div class="form-group">
                        <!-- Button -->
                        <div>
                            <button class="btn btn-success">Dołacz do bety</button>
                        </div>
                    </div>
                </fieldset>
            </form>
            </div>
            <hr>
            <div class="footer">
                <p>&copy; Marcin Ławniczak 2013-2014</p>
            </div>

        </div> <!-- /container -->

    </body>
</html>
