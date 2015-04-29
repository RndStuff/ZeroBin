<?php

if ( version_compare ( PHP_VERSION, '5.2.6' ) < 0 ) die( 'ZeroBin requires PHP 5.2.6 or above to work. Sorry.' );

require_once "config.inc.php";
require_once "lib/serversalt.php";
require_once "lib/vizhash_gd_zero.php";

// hardcodes the version as config files may not change
$cfg["version"]     = "Alpha 0.20.00";

// trafic_limiter : Make sure the IP address makes at most 1 request every 10 seconds.
// Will return false if IP address made a call less than 10 seconds ago.
function trafic_limiter_canPass($ip)
{
    global $cfg;
    $timeBetweenPosts = $cfg["timeBetweenPosts"];
    // -1: no rate limiting
    if($timeBetweenPosts == -1) {
        return true;
    }
    $tfilename = './'.$cfg[ 'dataDir' ].'/trafic_limiter.php';
    if (!is_file($tfilename))
    {
        file_put_contents($tfilename,"<?php\n\$GLOBALS['trafic_limiter']=array();\n?>");
        chmod($tfilename,0705);
    }
    require $tfilename;
    $tl=$GLOBALS['trafic_limiter'];
    if (!empty($tl[$ip]) && ($tl[$ip] + $timeBetweenPosts >=time()))
    {
        return false;
        // FIXME: purge file of expired IPs to keep it small
    }
    $tl[$ip]=time();
    file_put_contents($tfilename, "<?php\n\$GLOBALS['trafic_limiter']=".var_export($tl,true).";\n?>");
    return true;
}

// Constant time string comparison.
// (Used to deter time attacks on hmac checking. See section 2.7 of https://defuse.ca/audits/zerobin.htm)
function slow_equals ( $a, $b )
{
    $diff = strlen ( $a ) ^ strlen ( $b );
    for ( $i = 0; $i < strlen ( $a ) && $i < strlen ( $b ); $i++ )
    {
        $diff |= ord ( $a[ $i ] ) ^ ord ( $b[ $i ] );
    }

    return $diff === 0;
}


/* Convert paste id to storage path.
The idea is to creates subdirectories in order to limit the number of files per directory.
(A high number of files in a single directory can slow things down.)
eg. "f468483c313401e8" will be stored in "data/f4/68/f468483c313401e8"
High-trafic websites may want to deepen the directory structure (like Squid does).

eg. input 'e3570978f9e4aa90' --> output 'data/e3/57/'
*/
function dataid2path ( $dataid )
{
    global $cfg;

    return $cfg[ 'dataDir' ].'/'.substr ( $dataid, 0, 2 ).'/'.substr ( $dataid, 2, 2 ).'/';
}

/* Convert paste id to discussion storage path.
eg. 'e3570978f9e4aa90' --> 'data/e3/57/e3570978f9e4aa90.discussion/'
*/
function dataid2discussionpath ( $dataid )
{
    return dataid2path ( $dataid ).$dataid.'.discussion/';
}

// Checks if a json string is a proper SJCL encrypted message.
// False if format is incorrect.
function validSJCL ( $jsonstring )
{
    $accepted_keys = array('iv', 'v', 'iter', 'ks', 'ts', 'mode', 'adata', 'cipher', 'salt', 'ct');

// Make sure content is valid json
    $decoded = json_decode ( $jsonstring );
    if ( $decoded == NULL )
        return false;

    $decoded = (array)$decoded;

// Make sure required fields are present
    foreach ( $accepted_keys as $k )
    {
        if ( !array_key_exists ( $k, $decoded ) )
            return false;
    }

// Make sure some fields are base64 data
    if ( base64_decode ( $decoded[ 'iv' ], $strict = true ) == NULL )
    {
        return false;
    }
    if ( base64_decode ( $decoded[ 'salt' ], $strict = true ) == NULL )
    {
        return false;
    }
    if ( base64_decode ( $decoded[ 'cipher' ], $strict = true ) == NULL )
    {
        return false;
    }

// Make sure no additionnal keys were added.
    if ( count ( array_intersect ( array_keys ( $decoded ), $accepted_keys ) ) != 10 )
    {
        return false;
    }

// Reject data if entropy is too low
    $ct = base64_decode ( $decoded[ 'ct' ], $strict = true );
    if ( strlen ( $ct ) > strlen ( gzdeflate ( $ct ) ) )
        return false;

// Make sure some fields have a reasonable size.
    if ( strlen ( $decoded[ 'iv' ] ) > 24 ) return false;
    if ( strlen ( $decoded[ 'salt' ] ) > 14 ) return false;

    return true;
}

// Delete a paste and its discussion.
// Input: $pasteid : the paste identifier.
function deletePaste ( $pasteid )
{
    global $cfg;

    $path = dataid2path ( $pasteid );
    $dpath = dataid2discussionpath( $pasteid );

// Delete the paste itself and the salt
    unlink ( $path.$pasteid );
    unlink ( $path.$pasteid.$cfg[ 'saltAppend' ] );

// Delete discussion if it exists.
    if ( is_dir ( $dpath ) )
    {
// Delete all files in discussion directory
        $dhandle = opendir ( $dpath );
        while ( false !== ( $filename = readdir ( $dhandle ) ) )
        {
            if ( is_file ( $dpath.$filename ) )
                unlink ( $dpath.$filename );
        }
        closedir ( $dhandle );

// Delete the discussion directory.
        rmdir ( $dpath );
    }

    if ( count( glob( $path . "*" ) ) == 0 )
    {
        rmdir( $path );
    }
}

if ( !empty( $_POST[ 'data' ] ) ) // Create new paste/comment
{
    /* POST contains:
    data (mandatory) = json encoded SJCL encrypted text (containing keys: iv,salt,ct)

    All optional data will go to meta information:
    expire (optional) = expiration delay (never,5min,10min,1hour,1day,1week,1month,1year,burn) (default:never)
    opendiscusssion (optional) = is the discussion allowed on this paste ? (0/1) (default:0)
    syntaxcoloring (optional) = should this paste use syntax coloring when displaying.
    nickname (optional) = son encoded SJCL encrypted text nickname of author of comment (containing keys: iv,salt,ct)
    parentid (optional) = in discussion, which comment this comment replies to.
    pasteid (optional) = in discussion, which paste this comment belongs to.
    */

    header ( 'Content-type: application/json' );
    $error = false;

// Create storage directory if it does not exist.
    if ( !is_dir ( $cfg[ 'dataDir' ] ) )
    {
        mkdir ( $cfg[ 'dataDir' ], 0600 );

        if ( !is_dir ( $cfg[ 'dataDir' ] ) )
        {
            echo json_encode( array( 'status' => 0, 'message' => 'Administrator has not set the write permissions to the pastebin directory.') );
            exit;
        }

        file_put_contents ( $cfg[ 'dataDir' ].'/.htaccess', "Allow from none\nDeny from all\n", LOCK_EX );
        touch( $cfg[ 'dataDir' ].'/index.html' );
    }

// Make sure last paste from the IP address was more than 10 seconds ago.
    if ( !trafic_limiter_canPass ( $_SERVER[ 'REMOTE_ADDR' ] ) )
    {
        echo json_encode ( array('status' => 1, 'message' => 'Please wait '.$cfg["timeBetweenPosts"].' seconds between each post.') );
        exit;
    }

// Make sure content is not too big.
    $data = $_POST[ 'data' ];
    $maxPostSize = $cfg["maxPostSize"];

    if ( strlen ( $data ) > $maxPostSize * 1024 * 1024 )
    {
        echo json_encode ( array('status' => 1, 'message' => 'Paste is limited to '.$cfg["maxPostSize"].'MB of encrypted data.') );
        exit;
    }

// Make sure format is correct.
    if ( !validSJCL ( $data ) )
    {
        echo json_encode ( array('status' => 1, 'message' => 'Invalid data.') );
        exit;
    }

// Read additional meta-information.
    $meta = array();
    $meta[ 'postdate' ] = time ();

// Read expiration date
    if ( !empty( $_POST[ 'expire' ] ) )
    {
      $expire=$_POST['expire'];
      if(array_key_exists($expire, $cfg["expire"])) {
          // Valid expiration info
          $expireDelay = $cfg["expire"][$expire];
          if($expireDelay != -1) { // -1 means never
              $meta['expire_date'] = time() + $expireDelay;
          }
      } else {
          // Use default for an invalid POST expire name.
          // Will also be executed for empty keys
          $expireDelay = $cfg["expire"][$cfg["expireDefault"]];
          if($expireDelay != -1) { // -1 means never
              $meta['expire_date'] = time() + $expireDelay;
            }
      }
    }

// Destroy the paste when it is read.
    if ( !empty( $_POST[ 'burnafterreading' ] ) )
    {
        $burnafterreading = $_POST[ 'burnafterreading' ];
        if ( $burnafterreading != '0' && $burnafterreading != '1' )
        {
            $error = true;
        }
        if ( $burnafterreading != '0' )
        {
            $meta[ 'burnafterreading' ] = true;
        }
    }

// Read open discussion flag
    if ( !empty( $_POST[ 'opendiscussion' ] ) && $cfg["enableDiscussionSystem"])
    {
        $opendiscussion = $_POST[ 'opendiscussion' ];
        if ( $opendiscussion != '0' && $opendiscussion != '1' )
        {
            $error = true;
        }
        if ( $opendiscussion != '0' )
        {
            $meta[ 'opendiscussion' ] = true;
        }
    }

// Should we use syntax coloring when displaying ?
    if ( !empty( $_POST[ 'syntaxcoloring' ] ) && $cfg["enableSyntaxHighlighting"])
    {
        $syntaxcoloring = $_POST[ 'syntaxcoloring' ];
        if ( $syntaxcoloring != '0' && $syntaxcoloring != '1' )
        {
            $error = true;
        }
        if ( $syntaxcoloring != '0' )
        {
            $meta[ 'syntaxcoloring' ] = true;
        }
    }

// You can't have an open discussion on a "Burn after reading" paste:
    if ( isset( $meta[ 'burnafterreading' ] ) ) unset( $meta[ 'opendiscussion' ] );

    if( $cfg[ 'pasteidLength' ] <= 32)
    {
        $dataid = str_shuffle( substr ( hash ( 'md5', $data ), 0, $cfg[ 'pasteidLength' ] ) );
    }
    else
    {
        $dataid = str_shuffle ( substr ( md5 ( $data ) . generateRandomString( $cfg[ 'pasteidLength' ] , true) , 0, $cfg[ 'pasteidLength' ] ) );
    }

    $is_comment = ( !empty( $_POST[ 'parentid' ] ) && !empty( $_POST[ 'pasteid' ] ) ); // Is this post a comment ?
    $storage    = array('data' => $data);

    // Add meta-information only if necessary.
    if ( count ( $meta ) > 0 )
    {
        foreach( $meta as $index => $value )
        {
            $storage[ 'meta' ][ $index ] = $value;
        }
    }

    if ( $is_comment ) // The user posts a comment.
    {
        $pasteid  = $_POST[ 'pasteid' ];
        $parentid = $_POST[ 'parentid' ];
        if ( !preg_match ( '/\A[a-z0-9]+\z/', $pasteid ) )
        {
            echo json_encode ( array('status' => 1, 'message' => 'Invalid data.') );
            exit;
        }
        if ( !preg_match ( '/\A[a-z0-9]+\z/', $parentid ) )
        {
            echo json_encode ( array('status' => 1, 'message' => 'Invalid data.') );
            exit;
        }

        $storagedir = dataid2path ( $pasteid );
        if ( !is_file ( $storagedir.$pasteid ) )
        {
            echo json_encode ( array('status' => 1, 'message' => 'Invalid data.') );
            exit;
        }

        $paste = json_decode ( file_get_contents ( $storagedir.$pasteid ) );
        if ( !$paste->meta->opendiscussion )
        {
            echo json_encode ( array('status' => 1, 'message' => 'Invalid data.') );
            exit;
        }

        $discdir  = dataid2discussionpath ( $pasteid );
        $filename = $pasteid.'.'.$dataid.'.'.$parentid;
        if ( !is_dir ( $discdir ) ) mkdir ( $discdir, $mode = 0705, $recursive = true );
        if ( is_file ( $discdir.$filename ) ) // Oups... improbable collision.
        {
            echo json_encode ( array('status' => 1, 'message' => 'You are unlucky. Try again.') );
            exit;
        }

        if ( !empty( $_POST[ 'nickname' ] ) )
        {
            $nick = $_POST[ 'nickname' ];
            if ( !validSJCL ( $nick ) )
            {
                $error = true;
            }
            else
            {
                // Generation of the anonymous avatar (Vizhash):
                // If a nickname is provided, we generate a Vizhash.
                // (We assume that if the user did not enter a nickname, he/she wants
                // to be anonymous and we will not generate the vizhash.)

                $vz      = new vizhash64x64();
                $storage['meta'][ 'nickname' ] = $nick;
                $pngdata = $vz->generate ( $_SERVER[ 'REMOTE_ADDR' ], getPasteSalt ( $pasteid ) );
                if ( $pngdata != '' ) $storage['meta'][ 'vizhash' ] = 'data:image/png;base64,'.base64_encode ( $pngdata );
            }
        }

        if ( $error )
        {
            echo json_encode ( array('status' => 1, 'message' => 'Invalid data.') );
            exit;
        }

        unset( $storage[ 'expire_date' ] ); // Comment do not expire (it's the paste that expires)
        unset( $storage[ 'opendiscussion' ] );
        unset( $storage[ 'syntaxcoloring' ] );

        file_put_contents ( $discdir.$filename, json_encode ( $storage ), LOCK_EX );
        echo json_encode ( array('status' => 0, 'id' => $dataid) ); // 0 = no error
        exit;

    } else // a standard paste.
    {
        $storagedir = dataid2path ( $dataid );
        if ( !is_dir ( $storagedir ) ) mkdir ( $storagedir, $mode = 0705, $recursive = true );
        if ( is_file ( $storagedir.$dataid ) ) // Oups... improbable collision.
        {
            echo json_encode ( array('status' => 1, 'message' => 'You are unlucky. Try again.') );
            exit;
        }

        file_put_contents ( $storagedir.$dataid, json_encode ( $storage ), LOCK_EX );

        // Generate the "delete" token.
        // The token is the hmac of the pasteid signed with the server salt.
        // The paste can be delete by calling http://myserver.com/zerobin/?pasteid=<pasteid>&deletetoken=<deletetoken>
        $deletetoken = hash_hmac ( 'sha256', $dataid, getPasteSalt ($dataid) );

        echo json_encode(array('status'=>0,'id'=>$dataid,'deletetoken'=>$deletetoken,'showHash'=>$cfg['showHash'])); // 0 = no error
        exit;
    }

    echo json_encode ( array('status' => 1, 'message' => 'Server error.') );
    exit;
}

/* Process a paste deletion request.
Returns an array ('',$ERRORMESSAGE,$STATUS)
*/
function processPasteDelete ( $pasteid, $deletetoken )
{
    if ( preg_match ( '/\A[a-z0-9]+\z/', $pasteid ) )  // Is this a valid paste identifier ?
    {
        $filename = dataid2path ( $pasteid ).$pasteid;
        if ( !is_file ( $filename ) ) // Check that paste exists.
        {
            return array('', 'Paste does not exist, has expired or has been deleted.', '');
        }
    } else
    {
        return array('', 'Invalid data', '');
    }

    if ( !slow_equals ( $deletetoken, hash_hmac ( 'sha256', $pasteid, getPasteSalt ($pasteid) ) ) ) // Make sure token is valid.
    {
        return array('', 'Wrong deletion token. Paste was not deleted.', '');
    }

// Paste exists and deletion token is valid: Delete the paste.
    deletePaste ( $pasteid );

    return array('', '', 'Paste was properly deleted.');
}

/* Process a paste fetch request.
Returns an array ($CIPHERDATA,$ERRORMESSAGE,$STATUS)
*/
function processPasteFetch ( $pasteid )
{
    global $cfg;
    if ( preg_match ( '/\A[a-z0-9]+\z/', $pasteid ) )  // Is this a valid paste identifier ?
    {
        $filename = dataid2path ( $pasteid ).$pasteid;
        if ( !is_file ( $filename ) ) // Check that paste exists.
        {
            return array('', 'Paste does not exist, has expired, burned or has been deleted.', '');
        }
    } else
    {
        return array('', 'Invalid data', '');
    }

// Get the paste itself.
    $paste = json_decode ( file_get_contents ( $filename ) );

// See if paste has expired.
    if ( isset( $paste->meta->expire_date ) && $paste->meta->expire_date < time () )
    {
        deletePaste ( $pasteid );  // Delete the paste
        return array('', 'Paste does not exist, has expired or has been deleted.', '');
    }


    // We kindly provide the remaining time before expiration (in seconds)
    if ( property_exists ( $paste->meta, 'expire_date' ) ) $paste->meta->remaining_time = $paste->meta->expire_date - time ();

    $messages = array($paste); // The paste itself is the first in the list of encrypted messages.

    // If it's a discussion, get all comments, unless discussions are disabled
    if (property_exists($paste->meta, 'opendiscussion') && $paste->meta->opendiscussion && $cfg["enableDiscussionSystem"])
    {
        $comments = array();
        $datadir  = dataid2discussionpath ( $pasteid );
        if ( !is_dir ( $datadir ) ) mkdir ( $datadir, $mode = 0705, $recursive = true );
        $dhandle = opendir ( $datadir );
        while ( false !== ( $filename = readdir ( $dhandle ) ) )
        {
            if ( is_file ( $datadir.$filename ) )
            {
                $comment = json_decode ( file_get_contents ( $datadir.$filename ) );
                // Filename is in the form pasteid.commentid.parentid:
                // - pasteid is the paste this reply belongs to.
                // - commentid is the comment identifier itself.
                // - parentid is the comment this comment replies to (It can be pasteid)
                $items                                = explode ( '.', $filename );
                $comment->meta->commentid             = $items[ 1 ]; // Add some meta information not contained in file.
                $comment->meta->parentid              = $items[ 2 ];
                $comments[ $comment->meta->postdate ] = $comment; // Store in table
            }
        }
        closedir ( $dhandle );
        ksort ( $comments ); // Sort comments by date, oldest first.
        $messages = array_merge ( $messages, $comments );
    }
    $CIPHERDATA = json_encode ( $messages );

// If the paste was meant to be read only once, delete it.
    if ( property_exists ( $paste->meta, 'burnafterreading' ) && $paste->meta->burnafterreading ) deletePaste ( $pasteid );

    return array($CIPHERDATA, '', '');
}


$CIPHERDATA   = '';
$ERRORMESSAGE = '';
$STATUS       = '';

if ( !empty( $_GET[ 'deletetoken' ] ) && !empty( $_GET[ 'pasteid' ] ) ) // Delete an existing paste
{
    list ( $CIPHERDATA, $ERRORMESSAGE, $STATUS ) = processPasteDelete ( $_GET[ 'pasteid' ], $_GET[ 'deletetoken' ] );
} else if ( !empty( $_SERVER[ 'QUERY_STRING' ] ) )  // Return an existing paste.
{
    list ( $CIPHERDATA, $ERRORMESSAGE, $STATUS ) = processPasteFetch ( $_SERVER[ 'QUERY_STRING' ] );
}

require_once "lib/rain.tpl.class.php";
header ( 'Content-Type: text/html; charset=utf-8' );
$page = new RainTPL;
$page->assign ( 'cfg', $cfg );
$page->assign ( 'CIPHERDATA', htmlspecialchars ( $CIPHERDATA, ENT_NOQUOTES ) );  // We escape it here because ENT_NOQUOTES can't be used in RainTPL templates.
$page->assign ( 'VERSION', $cfg[ 'version' ] );
$page->assign ( 'ERRORMESSAGE', $ERRORMESSAGE );
$page->assign ( 'STATUS', $STATUS );
$page->draw ( 'page' );
?>
