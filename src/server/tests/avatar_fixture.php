<?php
declare(strict_types=1);
error_reporting(E_ALL & ~E_DEPRECATED);
ini_set('error_log',$argv[2].'/fixture-errors.log');
require $argv[1].'/app/Security/Admin.php';
function check($ok,string $message): void { if (!$ok) throw new RuntimeException($message); }
class FixturePDO {
    public bool $active=false; public bool $uncertain=false; public $db; public array $before=[];
    function inTransaction(): bool { return $this->active; }
    function beginTransaction(): bool { $this->before=$this->db->state; $this->active=true; return true; }
    function commit(): bool { $this->active=false; if($this->uncertain) throw new RuntimeException('synthetic uncertain commit'); return true; }
    function rollBack(): bool { $this->db->state=$this->before; $this->active=false; return true; }
}
class FixtureDB {
    public array $state=['username'=>'old','avatar'=>'old.png']; public bool $fail=false; public FixturePDO $pdo;
    function __construct() { $this->pdo=new FixturePDO();$this->pdo->db=$this; }
    function updateAdminUsername($name): void { $this->state['username']=$name; }
    function saveSystemSettings($v): void { if($this->fail) throw new RuntimeException('synthetic DB failure');$this->state['avatar']=$v['admin_avatar']; }
}
putenv('GUYI_AVATAR_DIR='.$argv[2]);$db=new FixtureDB();$im=imagecreatetruecolor(16,16);
$a=store_avatar_png($im);check(avatar_record_valid($a),'PNG record');check(getimagesize($a['path'])[2]===IMAGETYPE_PNG,'real PNG');
if (PHP_OS_FAMILY!=='Windows') check((fileperms($a['path'])&0777)===0640,'POSIX PNG mode');
commit_admin_profile($db,'new',$a,null);
check($db->state===['username'=>'new','avatar'=>$a['url']] && is_file($a['path']),'coherent success');
$b=store_avatar_png($im);$before=$db->state;$db->fail=true;
try { commit_admin_profile($db,'should-rollback',$b,null);throw new LogicException('expected failure'); }
catch (RuntimeException $e) { check($db->state===$before && !file_exists($b['path']),'rollback and owned cleanup'); }
$db->fail=false;
foreach (['javascript:alert(1)','http://example.invalid/avatar.png'] as $bad) {
    try { update_admin_profile($db,'must-not-change','url',null,$bad);throw new LogicException('invalid URL accepted'); }
    catch (InvalidArgumentException $e) { check($db->state===$before,'invalid URL changed profile'); }
}
try { update_admin_profile($db,'must-not-change','upload',['error'=>0,'size'=>8,'tmp_name'=>__FILE__],'');throw new LogicException('forged upload accepted'); }
catch (InvalidArgumentException $e) { check($db->state===$before,'forged upload changed profile'); }
$c=store_avatar_png($im);$db->pdo->uncertain=true;
try { commit_admin_profile($db,'possible-commit',$c,null);throw new LogicException('uncertain commit accepted'); }
catch (RuntimeException $e) { check(is_file($c['path']) && $db->state['avatar']===$c['url'],'uncertain commit deleted referenced PNG'); }
$db->pdo->uncertain=false;$copy=$c;$copy['path']=__FILE__;
try { discard_staged_avatar($copy);throw new LogicException('foreign cleanup accepted'); }
catch (RuntimeException $e) { check(is_file(__FILE__),'foreign file deleted'); }
foreach ([$argv[2].'/../'.basename($argv[2]),'relative/avatar-dir','php://memory',$argv[2].'/missing'] as $bad) {
    putenv('GUYI_AVATAR_DIR='.$bad);
    try { avatar_directory();throw new LogicException('bad directory accepted'); } catch(RuntimeException $e) {}
}
putenv('GUYI_AVATAR_DIR='.$argv[2]);
check(!is_file($argv[1].'/assets/ResourceStorage/'.basename($a['path'])),'wrote release tree');
imagedestroy($im);
echo json_encode(['ok'=>true,'png'=>'real GD encode','external_storage'=>true,'profile_atomic_failure'=>true,'uncertain_commit_retains_png'=>true,'forged_upload_rejected'=>true,'unsafe_path_rejected'=>true,'foreign_cleanup_rejected'=>true,'production_db_used'=>false,'posix_modes_tested'=>PHP_OS_FAMILY!=='Windows'],JSON_THROW_ON_ERROR)."\n";
