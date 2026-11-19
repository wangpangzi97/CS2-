<?php
declare(strict_types=1);
require_once __DIR__.'/Protocol.php';
final class DeviceProof {
    public const VERSION=1;
    // An enrolled card cannot use a freshly obtained legacy session to unbind,
    // reset its public key, or evict the legitimate device without its key.
    public static function verify(PDO $pdo,int $appId,string $card,string $device,string $raw,array $meta): void {
        $q=$pdo->prepare('SELECT k.public_key,k.device_hash FROM cards c JOIN data_device_keys k ON k.card_id=c.id AND k.data_epoch=c.data_epoch WHERE c.card_code=? AND c.app_id=?');$q->execute([$card,$appId]);$row=$q->fetch(PDO::FETCH_ASSOC);
        if (!$row) return; // First enrollment, or an explicit server/admin reset.
        if (!hash_equals($row['device_hash'],$device)) Protocol::fail(403,'Device proof required');
        if (!function_exists('sodium_crypto_sign_verify_detached')) Protocol::fail(503,'Device proof verifier unavailable');
        $encoded=$_SERVER['HTTP_X_DEVICE_PROOF'] ?? '';
        if (!is_string($encoded)||!preg_match('/^[A-Za-z0-9_-]{86}$/D',$encoded)) Protocol::fail(403,'Device proof required');
        $sig=base64_decode(strtr($encoded,'-_','+/').'==',true);$pub=base64_decode(strtr($row['public_key'],'-_','+/').'=',true);
        if ($sig===false||strlen($sig)!==64||$pub===false||strlen($pub)!==32) Protocol::fail(403,'Device proof required');
        $text=implode("\n",['guyi-device-v1','POST',parse_url($_SERVER['REQUEST_URI'] ?? '',PHP_URL_PATH),(string)$meta[2],(string)$meta[0],$meta[1],$_SERVER['HTTP_X_SESSION_ID'] ?? '',hash('sha256',$raw)]);
        if (!sodium_crypto_sign_verify_detached($sig,$text,$pub)) Protocol::fail(403,'Device proof required');
    }
}
