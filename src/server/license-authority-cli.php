<?php
declare(strict_types=1);
// Fixed server-side CLI adapter, not a public web endpoint. Secrets stay in the
// existing GuYi config and database; input/output pipes contain only proof/state.
if (PHP_SAPI!=='cli') { http_response_code(404);exit; }
ini_set('display_errors','0');
require_once __DIR__.'/LicenseAuthority.php';
try {
    $project=realpath($argv[1] ?? '');$appId=filter_var($argv[2] ?? '',FILTER_VALIDATE_INT);
    if (!$project||!$appId||$appId<1) throw new RuntimeException('configuration');
    require_once $project.'/config/config.php';
    require_once $project.'/app/Infrastructure/Database/Database.php';
    $raw=stream_get_contents(STDIN,8193);if (strlen($raw)>8192) throw new DataAuthorizationDenied();
    $in=json_decode($raw,true,12,JSON_THROW_ON_ERROR);if (!is_array($in)||array_is_list($in)) throw new DataAuthorizationDenied();
    $service=new LicenseAuthority((new Database())->pdo,$appId);
    if (($in['op'] ?? '')==='enroll') $identity=$service->enroll($in['enrollment'] ?? []);
    elseif (($in['op'] ?? '')==='check') $identity=$service->check($in['identity'] ?? [],$in['ip'] ?? '');
    elseif (($in['op'] ?? '')==='probe') { if (!defined('Database::DATA_AUTH_EPOCH_VERSION')||Database::DATA_AUTH_EPOCH_VERSION!==1) throw new RuntimeException('epoch patch required'); require_once $project.'/app/Security/DeviceProof.php'; if (DeviceProof::VERSION!==1||!function_exists('sodium_crypto_sign_verify_detached')||!str_contains(file_get_contents($project.'/app/Api/VerifyV2.php'),'DeviceProof::verify(')) throw new RuntimeException('device proof API patch required'); $db=new Database();$db->pdo->query('SELECT data_epoch FROM cards LIMIT 0');$db->pdo->query('SELECT binding_id FROM data_device_keys LIMIT 0');$identity=(object)[]; }
    else throw new DataAuthorizationDenied();
    echo json_encode(['ok'=>true,'identity'=>$identity],JSON_THROW_ON_ERROR);
} catch (DataAuthorizationDenied $e) { echo '{"ok":false,"error":"denied"}'; }
catch (Throwable $e) { fwrite(STDERR,"license authority unavailable\n");echo '{"ok":false,"error":"unavailable"}'; }
