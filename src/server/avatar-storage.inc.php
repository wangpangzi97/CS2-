<?php
declare(strict_types=1);
// Copied into the existing Admin.php by prepare_avatar_backend.py, never served.
function avatar_directory(): string {
    $dir = getenv('GUYI_AVATAR_DIR') ?: '/var/lib/guyi-access/avatars';
    if (str_contains($dir, "\0") || !preg_match('~^(?:/|[A-Za-z]:[\\\\/])~', $dir)) throw new RuntimeException('Absolute avatar directory required');
    $norm = static fn(string $s): string => rtrim(str_replace('\\', '/', $s), '/');
    $real = realpath($dir);
    if ($real === false || !is_dir($dir) || !is_writable($dir)) throw new RuntimeException('Avatar directory unavailable');
    $a=$norm($real); $b=$norm($dir);
    if (PHP_OS_FAMILY==='Windows') { $a=strtolower($a); $b=strtolower($b); }
    if ($a!==$b || $a==='') throw new RuntimeException('Canonical avatar directory required');
    for ($p=$dir;;$p=dirname($p)) {
        if (is_link($p)) throw new RuntimeException('Avatar symlink rejected');
        $parent=dirname($p); if ($parent===$p) break;
    }
    if (PHP_OS_FAMILY!=='Windows' && (fileperms($dir)&0002)!==0) throw new RuntimeException('World-writable avatar directory rejected');
    return $norm($real);
}
function avatar_record_valid(array $a): bool {
    if (array_keys($a)!==['directory','path','url','sha256','dev','ino']) return false;
    $dir=avatar_directory();
    if ($a['directory']!==$dir || !is_string($a['path']) || dirname($a['path'])!==$dir) return false;
    $name=basename($a['path']);
    if (!preg_match('/\Aavatar_[0-9a-f]{32}\.png\z/D',$name) || $a['url']!=='/media/avatars/'.$name) return false;
    $st=lstat($a['path']);
    return $st!==false && !is_link($a['path']) && ($st['mode']&0170000)===0100000 &&
        $st['dev']===$a['dev'] && $st['ino']===$a['ino'] &&
        is_string($a['sha256']) && hash_equals($a['sha256'],hash_file('sha256',$a['path']));
}
function discard_staged_avatar(array $a): void {
    // Never remove a replaced file, symlink, arbitrary caller path or old avatar.
    if (!avatar_record_valid($a) || !unlink($a['path'])) throw new RuntimeException('Owned avatar cleanup failed');
}
function store_avatar_png($image): array {
    $dir=avatar_directory();
    $name='avatar_'.bin2hex(random_bytes(16)).'.png';
    $path=$dir.'/'.$name;
    $old=umask(0027);
    try { $f=fopen($path,'xb'); } finally { umask($old); }
    if ($f===false) throw new RuntimeException('Avatar exclusive create failed');
    $created=fstat($f); $ok=false;
    try {
        if (!imagepng($image,$f) || !fflush($f)) throw new RuntimeException('Avatar encoding failed');
        if (function_exists('fsync') && !fsync($f)) throw new RuntimeException('Avatar sync failed');
        $st=fstat($f);
        if ($st['size']<1 || $st['size']>2097152 || !chmod($path,0640)) throw new RuntimeException('Avatar output limit/permissions');
        $ok=true;
    } finally {
        fclose($f);
        if (!$ok) {
            $now=lstat($path);
            if ($now!==false && !is_link($path) && $now['dev']===$created['dev'] && $now['ino']===$created['ino']) unlink($path);
        }
    }
    $st=lstat($path);
    return ['directory'=>$dir,'path'=>$path,'url'=>'/media/avatars/'.$name,
        'sha256'=>hash_file('sha256',$path),'dev'=>$st['dev'],'ino'=>$st['ino']];
}
function stage_avatar(array $file): array {
    if (($file['error']??1)!==UPLOAD_ERR_OK || !is_int($file['size']??null) || $file['size']<1 ||
        $file['size']>2097152 || !is_string($file['tmp_name']??null) || !is_uploaded_file($file['tmp_name'])) {
        throw new InvalidArgumentException('Invalid upload or larger than 2MiB');
    }
    $info=getimagesize($file['tmp_name']);
    if (!$info || $info[0]<1 || $info[1]<1 || $info[0]>2048 || $info[1]>2048 ||
        !in_array($info[2],[IMAGETYPE_JPEG,IMAGETYPE_PNG,IMAGETYPE_WEBP],true)) {
        throw new InvalidArgumentException('JPEG/PNG/WebP up to 2048 pixels required');
    }
    $image=imagecreatefromstring(file_get_contents($file['tmp_name']));
    if ($image===false) throw new InvalidArgumentException('Invalid image');
    try { return store_avatar_png($image); } finally { imagedestroy($image); }
}
function safe_avatar(array $file): string { return stage_avatar($file)['url']; }
function commit_admin_profile($db,string $username,?array $staged,?string $url): void {
    $username=trim($username);
    if ($username==='' || ($staged!==null && $url!==null)) throw new InvalidArgumentException('Invalid profile');
    if ($staged!==null && !avatar_record_valid($staged)) throw new RuntimeException('Invalid staged avatar');
    if ($url!==null) $url=safe_image_url($url);
    $begun=false; $commitAttempted=false;
    try {
        if ($db->pdo->inTransaction() || !$db->pdo->beginTransaction()) throw new RuntimeException('Profile transaction unavailable');
        $begun=true;
        $db->updateAdminUsername($username);
        $avatar=$staged!==null ? $staged['url'] : $url;
        if ($avatar!==null) $db->saveSystemSettings(['admin_avatar'=>$avatar]);
        $commitAttempted=true;
        if (!$db->pdo->commit()) throw new RuntimeException('Profile commit failed');
    } catch (Throwable $e) {
        $rolled=false;
        if ($begun && $db->pdo->inTransaction()) {
            try { $rolled=$db->pdo->rollBack(); } catch (Throwable $ignored) {}
        }
        if ($staged!==null && (!$commitAttempted || $rolled || !$begun)) {
            try { discard_staged_avatar($staged); } catch (Throwable $ignored) { error_log('Owned avatar cleanup requires review'); }
        } elseif ($staged!==null) {
            // An uncertain commit may already reference this PNG. Preserve it.
            error_log('Profile commit outcome unknown; staged avatar retained');
        }
        throw $e;
    }
}
function update_admin_profile($db,string $username,string $type,?array $upload,string $url): void {
    $username=trim($username);
    if ($username==='') throw new InvalidArgumentException('Username required');
    if (!in_array($type,['','upload','url'],true)) throw new InvalidArgumentException('Invalid avatar type');
    $staged=null; $imageUrl=null;
    if ($type==='upload') {
        if ($upload===null) throw new InvalidArgumentException('Upload required');
        $staged=stage_avatar($upload);
    } elseif ($type==='url' && trim($url)!=='') {
        $imageUrl=safe_image_url(trim($url));
    }
    commit_admin_profile($db,$username,$staged,$imageUrl);
}
