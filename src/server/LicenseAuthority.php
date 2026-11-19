<?php
declare(strict_types=1);

final class DataAuthorizationDenied extends RuntimeException {}

// This class is injected with a server-side PDO. It never returns a card, app
// secret or GuYi session key, and never calls verifyCard (which can reactivate).
final class LicenseAuthority {
    public function __construct(private PDO $pdo, private int $appId) {}
    private function deny(): never { throw new DataAuthorizationDenied('denied'); }
    private function text(array $a,string $key,int $max): string {
        $v=$a[$key] ?? null;
        if (!is_string($v)||$v===''||strlen($v)>$max||str_contains($v,"\0")) $this->deny();
        return $v;
    }
    private function hex(string $v,int $size): void { if (!preg_match('/^[a-f0-9]{'.$size.'}$/D',$v)) $this->deny(); }
    private function permitted(array $row,string $device,string $ip): void {
        if ((int)$row['app_status']!==1||(int)$row['status']!==1||(int)$row['active_status']!==1 ||
            !hash_equals((string)$row['device_hash'],$device)||!hash_equals((string)$row['active_device'],$device)||
            strtotime((string)$row['expire_time'])<=time()||strtotime((string)$row['active_expiry'])<=time()) $this->deny();
        $q=$this->pdo->prepare("SELECT id FROM blacklists WHERE (type='ip' AND value=?) OR (type='device' AND value=?) LIMIT 1");$q->execute([$ip,$device]);if ($q->fetch()) $this->deny();
    }
    private function rowById(string $id): array {
        if (!ctype_digit($id)||strlen($id)>10) $this->deny();
        // Explicit projection permits column-scoped SELECT; do not expand this
        // to c.* (card/custom/admin metadata is not an authorization input).
        $q=$this->pdo->prepare('SELECT c.id,c.status,c.device_hash,c.expire_time,c.data_epoch,a.status AS app_status,a.key_version,d.device_hash AS active_device,d.status AS active_status,d.expire_time AS active_expiry FROM cards c JOIN applications a ON a.id=c.app_id JOIN active_devices d ON d.card_code=c.card_code AND d.app_id=c.app_id WHERE c.id=? AND c.app_id=?');
        $q->execute([$id,$this->appId]);$r=$q->fetch(PDO::FETCH_ASSOC);if (!$r) $this->deny();return $r;
    }
    private function identity(array $row,array $key): array {
        return ['subject'=>(string)$row['id'],'device'=>(string)$key['device_hash'],'public_key'=>(string)$key['public_key'],'binding'=>(string)$key['binding_id'],'epoch'=>(int)$row['data_epoch'],'version'=>(int)$row['key_version'],'expires_at'=>min(strtotime($row['expire_time']),strtotime($row['active_expiry']))];
    }
    public function enroll(array $in): array {
        $sid=$this->text($in,'license_session',64);$device=$this->text($in,'device',64);$pub=$this->text($in,'public_key',43);$mac=$this->text($in,'mac',64);$text=$this->text($in,'text',2048);$ip=$this->text($in,'ip',45);
        $this->hex($sid,64);$this->hex($device,64);$this->hex($mac,64);
        if (!filter_var($ip,FILTER_VALIDATE_IP)||!preg_match('/^[A-Za-z0-9_-]{43}$/D',$pub)) $this->deny();
        $parts=explode("\n",$text);
        if (count($parts)!==8||$parts[0]!=='gamesense-data-enroll-v1'||!str_starts_with($parts[1],'https://')||$parts[5]!==$sid||$parts[6]!==$device||$parts[7]!==$pub||!ctype_digit($parts[4])||(int)$parts[4]<=time()||(int)$parts[4]>time()+90) $this->deny();
        $this->pdo->beginTransaction();
        try {
            $q=$this->pdo->prepare('SELECT s.expires_at,s.key_version,s.device_hash,c.id AS card_id,a.api_secret,a.key_version AS app_version FROM api_sessions s JOIN cards c ON c.card_code=s.card_code AND c.app_id=s.app_id JOIN applications a ON a.id=s.app_id WHERE s.session_id=? AND s.app_id=? FOR UPDATE');$q->execute([$sid,$this->appId]);$session=$q->fetch(PDO::FETCH_ASSOC);
            if (!$session||(int)$session['expires_at']<=time()||(int)$session['key_version']!==(int)$session['app_version']||!hash_equals($session['device_hash'],$device)) $this->deny();
            $secret=$session['api_secret'];$this->hex($secret,64);
            $sessionKey=hash_hkdf('sha256',hex2bin($secret),32,'guyi-v2/session',$sid);
            $key=hash_hkdf('sha256',$sessionKey,32,'guyi-v2/data-enrollment','');
            if (!hash_equals(hash_hmac('sha256',$text,$key),$mac)) $this->deny();
            $row=$this->rowById((string)$session['card_id']);$this->permitted($row,$device,$ip);
            $q=$this->pdo->prepare('SELECT * FROM data_device_keys WHERE card_id=? FOR UPDATE');$q->execute([$row['id']]);$binding=$q->fetch(PDO::FETCH_ASSOC);
            if ($binding&&(int)$binding['data_epoch']===(int)$row['data_epoch']) {
                if (!hash_equals($binding['public_key'],$pub)||!hash_equals($binding['device_hash'],$device)) $this->deny();
            } else {
                $binding=['device_hash'=>$device,'public_key'=>$pub,'binding_id'=>bin2hex(random_bytes(32))];
                $q=$this->pdo->prepare('INSERT INTO data_device_keys (card_id,device_hash,public_key,data_epoch,binding_id,updated_at) VALUES (?,?,?,?,?,?) ON DUPLICATE KEY UPDATE device_hash=VALUES(device_hash),public_key=VALUES(public_key),data_epoch=VALUES(data_epoch),binding_id=VALUES(binding_id),updated_at=VALUES(updated_at)');
                $q->execute([$row['id'],$device,$pub,$row['data_epoch'],$binding['binding_id'],time()]);
            }
            $r=$this->identity($row,$binding);$this->pdo->commit();return $r;
        } catch (Throwable $e) { if ($this->pdo->inTransaction()) $this->pdo->rollBack();throw $e; }
    }
    public function check(array $in,string $ip): array {
        if (!filter_var($ip,FILTER_VALIDATE_IP)) $this->deny();
        $id=$this->text($in,'subject',10);$device=$this->text($in,'device',64);$pub=$this->text($in,'public_key',43);$binding=$this->text($in,'binding',64);
        $row=$this->rowById($id);$this->permitted($row,$device,$ip);
        $q=$this->pdo->prepare('SELECT * FROM data_device_keys WHERE card_id=?');$q->execute([$id]);$key=$q->fetch(PDO::FETCH_ASSOC);
        if (!$key||(int)($in['epoch'] ?? 0)!==(int)$row['data_epoch']||(int)($in['version'] ?? 0)!==(int)$row['key_version']||(int)$key['data_epoch']!==(int)$row['data_epoch']||!hash_equals($key['binding_id'],$binding)||!hash_equals($key['public_key'],$pub)||!hash_equals($key['device_hash'],$device)) $this->deny();
        return $this->identity($row,$key);
    }
}
