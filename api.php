<?php
/* ============================================================
   AUREX · Backend de sincronización (api.php)
   - Login con usuario/clave (sin cuenta externa)
   - Datos compartidos entre todos los usuarios
   - Almacenamiento de archivos adjuntos (expedientes)
   Requisitos: PHP 7.4+ con permiso de escritura en ./data
   ============================================================ */

error_reporting(E_ALL & ~E_DEPRECATED & ~E_NOTICE);
ini_set('display_errors', '0');

$DATA = __DIR__ . '/data';
$FILES = $DATA . '/files';
@mkdir($DATA, 0775, true);
@mkdir($FILES, 0775, true);
// proteger el directorio de datos ante accesos directos
if (!is_file($DATA . '/.htaccess')) @file_put_contents($DATA . '/.htaccess', "Require all denied\nDeny from all\n");

$TOKEN_TTL = 60 * 60 * 24 * 30; // 30 días

function jexit($o, $code = 200) { http_response_code($code); header('Content-Type: application/json; charset=utf-8'); echo json_encode($o); exit; }
function body_json() { $b = file_get_contents('php://input'); $j = json_decode($b, true); return is_array($j) ? $j : []; }
function lock() { $f = fopen($GLOBALS['DATA'] . '/.lock', 'c'); if ($f) flock($f, LOCK_EX); return $f; }
function unlock($f) { if ($f) { flock($f, LOCK_UN); fclose($f); } }
function jload($name, $def) { $p = $GLOBALS['DATA'] . "/$name.json"; if (!is_file($p)) return $def; $j = json_decode(file_get_contents($p), true); return $j === null ? $def : $j; }
function jsave($name, $o) { file_put_contents($GLOBALS['DATA'] . "/$name.json", json_encode($o)); }

/* ---------- usuarios ---------- */
function users_init() {
  $u = jload('users', null);
  if ($u !== null) return $u;
  $u = [
    ['u'=>'admin','nombre'=>'Administrador','rol'=>'admin','h'=>hash('sha256','aurex:admin:aurex2026'),'cambiar'=>false],
    ['u'=>'alexis','nombre'=>'Alexis','rol'=>'acopiador','h'=>hash('sha256','aurex:alexis:alexis123'),'cambiar'=>true],
    ['u'=>'rubi','nombre'=>'Rubi','rol'=>'contabilidad','h'=>'3aae9f0389380c36ecdaf0338a80a12e7e08b7dad37edb0595f16a64fe5d60e7','cambiar'=>true],
    ['u'=>'michael','nombre'=>'Michael','rol'=>'comercial','h'=>'e2b740cf25b4ba4a46969fea35c70f7f9535fc81a50a51532fb3adade55d6264','cambiar'=>true],
    ['u'=>'victor','nombre'=>'Victor','rol'=>'planta','h'=>'4c491f66f3f0c67e289bbb31fcc6af9ea5e6dcdfde3c530484682d5c6a191eb6','cambiar'=>true],
    ['u'=>'pedro','nombre'=>'Pedro','rol'=>'gerencia','h'=>'13b483c0a066c7c050bc9eb9a4abbb3ca6fee7a959d5434adaf425eb2519a297','cambiar'=>true],
    ['u'=>'micaela','nombre'=>'Micaela','rol'=>'planta','h'=>'b69ff12cb48c47711aa4dabe397e85b206c8469fa3f7f2d6403ec4307da4a434','cambiar'=>true],
    ['u'=>'juancarlos','nombre'=>'Juan Carlos','rol'=>'planta','h'=>'4ceea5278d4d360a0482131d435483bfa7624a96d90e45bc0d89861c00f9de3d','cambiar'=>true],
  ];
  jsave('users', $u);
  return $u;
}
function users_public($users) {
  return array_map(function($x){ return ['u'=>$x['u'],'nombre'=>$x['nombre'],'rol'=>$x['rol'],'cambiar'=>!empty($x['cambiar'])]; }, $users);
}
function users_find(&$users, $u) { foreach ($users as $i=>$x) if ($x['u'] === $u) return $i; return -1; }

/* ---------- tokens ---------- */
function tokens_load() { return jload('tokens', []); }
function token_user($tok) {
  if (!$tok) return null;
  $t = tokens_load();
  if (!isset($t[$tok])) return null;
  if (time() - $t[$tok]['t'] > $GLOBALS['TOKEN_TTL']) return null;
  return $t[$tok]['u'];
}
function token_issue($u) {
  $f = lock();
  $t = tokens_load();
  // limpiar expirados
  foreach ($t as $k=>$v) if (time() - $v['t'] > $GLOBALS['TOKEN_TTL']) unset($t[$k]);
  $tok = bin2hex(random_bytes(24));
  $t[$tok] = ['u'=>$u,'t'=>time()];
  jsave('tokens', $t);
  unlock($f);
  return $tok;
}
function auth_user() {
  $tok = $_SERVER['HTTP_X_TOKEN'] ?? '';
  return token_user($tok);
}
function require_user() {
  $u = auth_user();
  if (!$u) jexit(['auth'=>1,'err'=>'Sesión no válida'], 401);
  return $u;
}
function current_role($uname) {
  $users = users_init();
  $i = users_find($users, $uname);
  return $i >= 0 ? $users[$i]['rol'] : null;
}

/* ---------- permisos de escritura por clave ---------- */
function may_write($role, $key) {
  if ($role === 'admin' || $role === 'comercial') return true;
  $map = [
    'contabilidad' => ['pagos','liq','vta','prf','fac'],
    'planta' => ['ingreso','proc','rley','pendRec','pend','fix','px'],
    'acopiador' => ['acop','fac'],
    'gerencia' => [],
  ];
  $allowed = $map[$role] ?? [];
  return in_array($key, $allowed, true);
}

/* ---------- store de datos ---------- */
function store_load() { return jload('store', ['keys'=>new stdClass(),'log'=>[],'logn'=>0]); }

$action = $_GET['a'] ?? '';

/* ===================== endpoints públicos ===================== */
if ($action === 'ping') { jexit(['srv'=>true]); }

if ($action === 'userlist') {
  $users = users_init();
  jexit(['users'=>array_map(function($x){ return ['u'=>$x['u'],'nombre'=>$x['nombre']]; }, $users)]);
}

if ($action === 'login') {
  $b = body_json();
  $u = strtolower(trim($b['u'] ?? ''));
  $p = (string)($b['p'] ?? '');
  $users = users_init();
  $i = users_find($users, $u);
  if ($i < 0 || !hash_equals($users[$i]['h'], hash('sha256', "aurex:$u:$p"))) {
    jexit(['err'=>'Usuario o clave incorrectos'], 401);
  }
  $tok = token_issue($u);
  jexit(['token'=>$tok, 'user'=>['u'=>$u,'nombre'=>$users[$i]['nombre'],'rol'=>$users[$i]['rol'],'cambiar'=>!empty($users[$i]['cambiar'])]]);
}

/* ===================== endpoints con sesión ===================== */
$ME = require_user();
$ROLE = current_role($ME);
$users = users_init();

if ($action === 'me') {
  $i = users_find($users, $ME);
  jexit(['user'=>['u'=>$ME,'nombre'=>$users[$i]['nombre'],'rol'=>$users[$i]['rol'],'cambiar'=>!empty($users[$i]['cambiar'])]]);
}

if ($action === 'sync') {
  $b = body_json();
  $revs = $b['revs'] ?? [];
  $full = !empty($b['full']);
  $clogn = isset($b['logn']) ? intval($b['logn']) : 0;
  $store = store_load();
  $keys = [];
  foreach ((array)$store['keys'] as $k=>$o) {
    if ($full || !isset($revs[$k]) || $revs[$k] != $o['rev']) $keys[$k] = $o;
  }
  $resp = ['keys'=>(object)$keys, 'users'=>users_public($users), 'logn'=>intval($store['logn'])];
  if ($full || $clogn < intval($store['logn'])) $resp['log'] = $store['log'];
  if ($full && count((array)$store['keys']) === 0) $resp['empty'] = true;
  jexit($resp);
}

if ($action === 'seed') {
  $b = body_json();
  $f = lock();
  $store = store_load();
  if (count((array)$store['keys']) === 0) { // solo si está vacío
    $keys = [];
    foreach (($b['keys'] ?? []) as $k=>$v) $keys[$k] = ['v'=>(string)$v, 'rev'=>1];
    $store['keys'] = $keys;
    $store['log'] = array_values($b['log'] ?? []);
    $store['logn'] = count($store['log']);
    jsave('store', $store);
  }
  unlock($f);
  jexit(['ok'=>1]);
}

if ($action === 'save') {
  $b = body_json();
  $key = (string)($b['key'] ?? '');
  if ($key === '' || $key === 'users' || $key === 'log') jexit(['err'=>'clave no válida'], 400);
  if (!may_write($ROLE, $key)) jexit(['perm'=>1,'err'=>'Sin permiso para modificar esta sección'], 403);
  $f = lock();
  $store = store_load();
  $cur = isset($store['keys'][$key]) ? $store['keys'][$key] : null;
  $crev = $cur ? intval($cur['rev']) : 0;
  $rev = isset($b['rev']) ? intval($b['rev']) : 0;
  if ($cur && $rev !== $crev) { // conflicto
    unlock($f);
    jexit(['conflict'=>1, 'v'=>$cur['v'], 'rev'=>$crev]);
  }
  $nrev = $crev + 1;
  $store['keys'][$key] = ['v'=>(string)($b['v'] ?? ''), 'rev'=>$nrev];
  jsave('store', $store);
  unlock($f);
  jexit(['rev'=>$nrev]);
}

if ($action === 'log') {
  $b = body_json();
  $f = lock();
  $store = store_load();
  foreach (($b['entries'] ?? []) as $e) $store['log'][] = $e;
  if (count($store['log']) > 5000) $store['log'] = array_slice($store['log'], -5000);
  $store['logn'] = count($store['log']);
  jsave('store', $store);
  unlock($f);
  jexit(['logn'=>intval($store['logn'])]);
}

/* ---------- gestión de usuarios (solo admin salvo chpw/chun propios) ---------- */
function save_users($users) { jsave('users', $users); }

if ($action === 'chpw') { // cambiar la propia clave
  $b = body_json();
  $p = (string)($b['p'] ?? '');
  if (strlen($p) < 6) jexit(['err'=>'Clave muy corta'], 400);
  $f = lock(); $users = users_init(); $i = users_find($users, $ME);
  $users[$i]['h'] = hash('sha256', "aurex:$ME:$p"); $users[$i]['cambiar'] = false;
  save_users($users); unlock($f);
  jexit(['ok'=>1]);
}

if ($action === 'chun') { // cambiar nombre/usuario propio
  $b = body_json();
  $nom = trim($b['nombre'] ?? '');
  $n = strtolower(trim($b['n'] ?? ''));
  $p = (string)($b['p'] ?? '');
  $f = lock(); $users = users_init(); $i = users_find($users, $ME);
  if ($nom !== '') $users[$i]['nombre'] = $nom;
  if ($n !== '' && $n !== $ME) {
    if (!preg_match('/^[a-z0-9._-]{3,30}$/', $n) || users_find($users, $n) >= 0) { unlock($f); jexit(['err'=>'Usuario inválido o ya existe'], 400); }
    if (!hash_equals($users[$i]['h'], hash('sha256', "aurex:$ME:$p"))) { unlock($f); jexit(['err'=>'Tu clave actual no coincide'], 400); }
    $users[$i]['u'] = $n; $users[$i]['h'] = hash('sha256', "aurex:$n:$p");
    $me2 = $n;
  } else { $me2 = $ME; }
  save_users($users); unlock($f);
  $j = users_find($users, $me2);
  jexit(['users'=>users_public($users), 'user'=>['u'=>$me2,'nombre'=>$users[$j]['nombre'],'rol'=>$users[$j]['rol'],'cambiar'=>!empty($users[$j]['cambiar'])]]);
}

// las siguientes requieren admin
function require_admin($role) { if ($role !== 'admin') jexit(['err'=>'Solo un administrador puede hacer esto'], 403); }

if ($action === 'u_add') {
  require_admin($ROLE);
  $b = body_json();
  $u = strtolower(trim($b['u'] ?? '')); $p = (string)($b['p'] ?? '');
  if (!preg_match('/^[a-z0-9._-]{3,30}$/', $u) || strlen($p) < 6) jexit(['err'=>'Usuario o clave inválidos'], 400);
  $f = lock(); $users = users_init();
  if (users_find($users, $u) >= 0) { unlock($f); jexit(['err'=>'Ese usuario ya existe'], 400); }
  $users[] = ['u'=>$u,'nombre'=>trim($b['nombre'] ?? $u) ?: $u,'rol'=>($b['rol'] ?? 'comercial'),'h'=>hash('sha256',"aurex:$u:$p"),'cambiar'=>true];
  save_users($users); unlock($f);
  jexit(['users'=>users_public($users)]);
}

if ($action === 'u_role') {
  require_admin($ROLE);
  $b = body_json(); $u = $b['u'] ?? ''; $rol = $b['rol'] ?? '';
  $f = lock(); $users = users_init(); $i = users_find($users, $u);
  if ($i < 0) { unlock($f); jexit(['err'=>'No existe'], 400); }
  $admins = count(array_filter($users, function($x){ return $x['rol']==='admin'; }));
  if ($users[$i]['rol']==='admin' && $rol!=='admin' && $admins < 2) { unlock($f); jexit(['err'=>'Debe quedar al menos un administrador'], 400); }
  $users[$i]['rol'] = $rol; save_users($users); unlock($f);
  jexit(['users'=>users_public($users)]);
}

if ($action === 'u_pw') {
  require_admin($ROLE);
  $b = body_json(); $u = $b['u'] ?? ''; $p = (string)($b['p'] ?? '');
  if (strlen($p) < 6) jexit(['err'=>'Clave muy corta'], 400);
  $f = lock(); $users = users_init(); $i = users_find($users, $u);
  if ($i < 0) { unlock($f); jexit(['err'=>'No existe'], 400); }
  $users[$i]['h'] = hash('sha256', "aurex:$u:$p"); $users[$i]['cambiar'] = true;
  save_users($users); unlock($f);
  jexit(['users'=>users_public($users)]);
}

if ($action === 'u_ren') {
  require_admin($ROLE);
  $b = body_json(); $u = $b['u'] ?? ''; $n = strtolower(trim($b['n'] ?? '')); $p = (string)($b['p'] ?? '');
  if (!preg_match('/^[a-z0-9._-]{3,30}$/', $n) || strlen($p) < 6) jexit(['err'=>'Datos inválidos'], 400);
  $f = lock(); $users = users_init(); $i = users_find($users, $u);
  if ($i < 0) { unlock($f); jexit(['err'=>'No existe'], 400); }
  if ($n !== $u && users_find($users, $n) >= 0) { unlock($f); jexit(['err'=>'Ese usuario ya existe'], 400); }
  $users[$i]['u'] = $n; $users[$i]['nombre'] = trim($b['nombre'] ?? $users[$i]['nombre']); $users[$i]['h'] = hash('sha256', "aurex:$n:$p"); $users[$i]['cambiar'] = true;
  save_users($users); unlock($f);
  jexit(['users'=>users_public($users)]);
}

if ($action === 'u_del') {
  require_admin($ROLE);
  $b = body_json(); $u = $b['u'] ?? '';
  $f = lock(); $users = users_init(); $i = users_find($users, $u);
  if ($i < 0) { unlock($f); jexit(['err'=>'No existe'], 400); }
  $admins = count(array_filter($users, function($x){ return $x['rol']==='admin'; }));
  if ($u === $ME || ($users[$i]['rol']==='admin' && $admins < 2)) { unlock($f); jexit(['err'=>'No puedes eliminar tu usuario ni al único administrador'], 400); }
  array_splice($users, $i, 1); save_users($users); unlock($f);
  jexit(['users'=>users_public($users)]);
}

/* ---------- archivos adjuntos ---------- */
function file_path($k) { return $GLOBALS['FILES'] . '/' . hash('sha256', $k); }

if ($action === 'fput') {
  $k = $_GET['k'] ?? '';
  if ($k === '') jexit(['err'=>'falta k'], 400);
  $raw = file_get_contents('php://input');
  file_put_contents(file_path($k), $raw);
  file_put_contents(file_path($k) . '.meta', json_encode(['name'=>$_GET['name'] ?? '', 'type'=>$_GET['type'] ?? '']));
  jexit(['ok'=>1]);
}

if ($action === 'fget') {
  $k = $_GET['k'] ?? '';
  $p = file_path($k);
  if ($k === '' || !is_file($p)) { http_response_code(404); exit; }
  $meta = json_decode(@file_get_contents($p . '.meta'), true) ?: [];
  header('Content-Type: application/octet-stream');
  header('X-Type: ' . rawurlencode($meta['type'] ?? ''));
  header('X-Name: ' . rawurlencode($meta['name'] ?? ''));
  header('Content-Length: ' . filesize($p));
  readfile($p);
  exit;
}

if ($action === 'fdel') {
  $k = $_GET['k'] ?? '';
  @unlink(file_path($k)); @unlink(file_path($k) . '.meta');
  jexit(['ok'=>1]);
}

jexit(['err'=>'acción desconocida: ' . $action], 400);
