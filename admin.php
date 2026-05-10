<?php
ob_start();
@ini_set('display_errors', '0');
error_reporting(0);

// ================================================
// SESSÃO SEGURA
// ================================================
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', '1');
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    ini_set('session.cookie_secure', '1');
}
session_start();

define('SESSION_TIMEOUT', 1800);   // 30 min de inatividade
define('MAX_LOGIN_ATTEMPTS', 5);   // tentativas antes do bloqueio
define('LOCKOUT_SECONDS', 900);    // 15 min bloqueado

// ================================================
// FUNÇÕES DE SEGURANÇA
// ================================================
function getClientIP() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
}

function getCSRFToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verifyCSRF($token) {
    return !empty($_SESSION['csrf_token'])
        && is_string($token)
        && hash_equals($_SESSION['csrf_token'], $token);
}

function lerAttempts($file) {
    if (!file_exists($file)) return [];
    $d = json_decode(@file_get_contents($file), true);
    return is_array($d) ? $d : [];
}

function salvarAttempts($file, $data) {
    $now = time();
    foreach ($data as $ip => $info) {
        $lockedExpired  = ($info['locked_until'] ?? 0) < $now;
        $stale          = isset($info['last']) && ($now - $info['last']) > 7200;
        if ($lockedExpired && $stale) unset($data[$ip]);
    }
    file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT), LOCK_EX);
    @chmod($file, 0600);
}

function checkLockout($file, $ip) {
    $data = lerAttempts($file);
    if (!isset($data[$ip])) return false;
    $lu = $data[$ip]['locked_until'] ?? 0;
    return ($lu > time()) ? $lu : false;
}

function recordFailedAttempt($file, $ip) {
    $data = lerAttempts($file);
    if (!isset($data[$ip])) $data[$ip] = ['count' => 0, 'last' => time(), 'locked_until' => 0];
    $data[$ip]['count']++;
    $data[$ip]['last'] = time();
    if ($data[$ip]['count'] >= MAX_LOGIN_ATTEMPTS) {
        $data[$ip]['locked_until'] = time() + LOCKOUT_SECONDS;
        $data[$ip]['count'] = 0;
    }
    salvarAttempts($file, $data);
    return $data[$ip]['count'];
}

function clearFailedAttempts($file, $ip) {
    $data = lerAttempts($file);
    unset($data[$ip]);
    salvarAttempts($file, $data);
}

function logAudit($file, $action, $details = '') {
    $log = [];
    if (file_exists($file)) $log = json_decode(@file_get_contents($file), true) ?: [];
    array_unshift($log, [
        'ts'      => date('Y-m-d H:i:s'),
        'ip'      => getClientIP(),
        'action'  => $action,
        'details' => mb_substr($details, 0, 200),
    ]);
    if (count($log) > 500) $log = array_slice($log, 0, 500);
    file_put_contents($file, json_encode($log, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
    @chmod($file, 0600);
}

// ================================================
// CREDENCIAIS
// ================================================
$cred_file      = __DIR__ . '/.admin_credentials';
$attempts_file  = __DIR__ . '/.login_attempts.json';
$audit_file     = __DIR__ . '/.audit_log.json';

if (!file_exists($cred_file)) {
    $default = ['user' => 'admin', 'hash' => password_hash('admin', PASSWORD_BCRYPT)];
    file_put_contents($cred_file, json_encode($default));
    @chmod($cred_file, 0600);
}
$creds      = json_decode(file_get_contents($cred_file), true);
$admin_user = $creds['user'] ?? 'admin';
$admin_hash = $creds['hash'] ?? '';

$salas_json    = __DIR__ . '/salas.json';
$galeria_json  = __DIR__ . '/galeria_home.json';
$pontos_json   = __DIR__ . '/pontos_estrategicos.json';
$clientes_json = __DIR__ . '/clientes.json';

// ================================================
// SESSION TIMEOUT CHECK
// ================================================
$is_logged_in = isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true;
if ($is_logged_in) {
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > SESSION_TIMEOUT) {
        session_unset();
        session_destroy();
        header('Location: admin.php?timeout=1');
        exit;
    }
    $_SESSION['last_activity'] = time();
}

// ================================================
// LOGIN
// ================================================
$login_error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    if (!verifyCSRF($_POST['csrf_token'] ?? '')) {
        $login_error = 'Erro de segurança. Recarregue a página e tente novamente.';
    } else {
        $client_ip    = getClientIP();
        $locked_until = checkLockout($attempts_file, $client_ip);
        if ($locked_until) {
            $wait_min    = max(1, (int) ceil(($locked_until - time()) / 60));
            $login_error = "Acesso bloqueado por excesso de tentativas. Tente em {$wait_min} minuto(s).";
        } elseif ($_POST['username'] === $admin_user && password_verify($_POST['password'], $admin_hash)) {
            clearFailedAttempts($attempts_file, $client_ip);
            session_regenerate_id(true);
            $_SESSION['admin_logged_in'] = true;
            $_SESSION['last_activity']   = time();
            $_SESSION['admin_ip']        = $client_ip;
            $is_logged_in                = true;
            logAudit($audit_file, 'login_success', 'user=' . $admin_user);
        } else {
            $count     = recordFailedAttempt($attempts_file, $client_ip);
            $remaining = max(0, MAX_LOGIN_ATTEMPTS - $count);
            if ($remaining > 0) {
                $login_error = "Usuário ou senha incorretos. Tentativas restantes: {$remaining}.";
            } else {
                $login_error = 'Conta bloqueada por 15 minutos por excesso de tentativas.';
            }
            logAudit($audit_file, 'login_failed', 'IP=' . $client_ip);
        }
    }
}

// LOGOUT
if (isset($_GET['logout'])) {
    logAudit($audit_file, 'logout', 'user=' . ($admin_user ?? ''));
    session_unset();
    session_destroy();
    header('Location: admin.php');
    exit;
}

// =========================================================
// Funções auxiliares
// =========================================================
function lerSalas($file) {
    if (!file_exists($file)) return ['salas' => []];
    $raw = @file_get_contents($file);
    if (!$raw) return ['salas' => []];
    $d = json_decode($raw, true);
    return (is_array($d) && isset($d['salas'])) ? $d : ['salas' => []];
}
function salvarJSON($file, $data) {
    // Backup automático antes de sobrescrever (últimos 5 por arquivo)
    if (file_exists($file) && filesize($file) > 10) {
        $bk_dir = __DIR__ . '/backups';
        if (!is_dir($bk_dir)) @mkdir($bk_dir, 0755, true);
        $bk = $bk_dir . '/' . basename($file, '.json') . '_' . date('Ymd_His') . '.json';
        @copy($file, $bk);
        // Mantém só os 5 mais recentes por arquivo
        $lista = glob($bk_dir . '/' . basename($file, '.json') . '_*.json') ?: [];
        sort($lista);
        foreach (array_slice($lista, 0, max(0, count($lista) - 5)) as $old) @unlink($old);
    }
    if (file_exists($file) && !is_writable($file)) @chmod($file, 0666);
    return file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), LOCK_EX) !== false;
}
function processarUpload($file_entry, $prefix, $upload_dir, $allow_video = true) {
    if ($file_entry['error'] !== UPLOAD_ERR_OK) return false;

    $mime = strtolower(@mime_content_type($file_entry['tmp_name']) ?: '');
    $ext  = strtolower(pathinfo($file_entry['name'], PATHINFO_EXTENSION));

    $img_mimes = ['image/jpeg','image/jpg','image/png','image/gif','image/webp'];
    $vid_mimes = ['video/mp4','video/quicktime','video/webm','video/x-msvideo','video/mov','video/x-matroska','application/octet-stream'];
    $img_exts  = ['jpg','jpeg','png','gif','webp'];
    $vid_exts  = ['mp4','mov','webm','avi','mkv','m4v'];

    $allowed_mimes = $allow_video ? array_merge($img_mimes, $vid_mimes) : $img_mimes;
    $allowed_exts  = $allow_video ? array_merge($img_exts, $vid_exts) : $img_exts;

    // Aceita se MIME ou extensão for válida (celulares às vezes enviam mime errado)
    $mime_ok = in_array($mime, $allowed_mimes);
    $ext_ok  = in_array($ext, $allowed_exts);
    if (!$mime_ok && !$ext_ok) return false;
    if (!in_array($ext, $allowed_exts)) $ext = 'jpg';

    if (!is_dir($upload_dir)) @mkdir($upload_dir, 0755, true);

    $filename = $prefix . '_' . time() . '_' . mt_rand(1000,9999) . '.' . $ext;
    $fullpath = rtrim($upload_dir, '/') . '/' . $filename;
    if (!move_uploaded_file($file_entry['tmp_name'], $fullpath)) return false;
    @chmod($fullpath, 0644);

    // Otimiza imagens server-side (backup caso o cliente não tenha suporte a canvas)
    if (in_array($ext, ['jpg','jpeg','png','webp']) && function_exists('imagecreatetruecolor')) {
        otimizarImagem($fullpath, $ext);
    }

    $rel = ltrim(str_replace(__DIR__, '', $fullpath), '/\\');
    return $rel;
}

function otimizarImagem($filepath, $ext) {
    $max_dim = 1500;
    $img = null;
    switch ($ext) {
        case 'jpg': case 'jpeg': $img = @imagecreatefromjpeg($filepath); break;
        case 'png':  $img = @imagecreatefrompng($filepath);  break;
        case 'webp': $img = @imagecreatefromwebp($filepath); break;
    }
    if (!$img) return;
    $w = imagesx($img);
    $h = imagesy($img);
    if ($w <= $max_dim && $h <= $max_dim) { imagedestroy($img); return; }

    $ratio = min($max_dim / $w, $max_dim / $h);
    $nw    = max(1, (int) round($w * $ratio));
    $nh    = max(1, (int) round($h * $ratio));

    $dest = imagecreatetruecolor($nw, $nh);
    if (in_array($ext, ['png', 'webp'])) {
        imagealphablending($dest, false);
        imagesavealpha($dest, true);
        imagefilledrectangle($dest, 0, 0, $nw, $nh, imagecolorallocatealpha($dest, 255, 255, 255, 127));
    }
    imagecopyresampled($dest, $img, 0, 0, 0, 0, $nw, $nh, $w, $h);

    switch ($ext) {
        case 'jpg': case 'jpeg': imagejpeg($dest, $filepath, 85); break;
        case 'png':  imagepng($dest, $filepath, 8);          break;
        case 'webp': imagewebp($dest, $filepath, 85);         break;
    }
    imagedestroy($img);
    imagedestroy($dest);
}
// Normaliza array de arquivos múltiplos para array de entries
function normalizarArquivos($files) {
    $result = [];
    if (isset($files['name'])) {
        if (is_array($files['name'])) {
            for ($i = 0; $i < count($files['name']); $i++) {
                if ($files['error'][$i] === UPLOAD_ERR_OK) {
                    $result[] = [
                        'name'     => $files['name'][$i],
                        'tmp_name' => $files['tmp_name'][$i],
                        'error'    => $files['error'][$i],
                        'size'     => $files['size'][$i],
                    ];
                }
            }
        } else {
            if ($files['error'] === UPLOAD_ERR_OK) $result[] = $files;
        }
    }
    return $result;
}

// =========================================================
// ENDPOINT AJAX — retorna JSON
// =========================================================
if ($is_logged_in && isset($_GET['ajax'])) {
    ob_clean();
    header('Content-Type: application/json; charset=utf-8');
    $ajax_action = $_GET['ajax'];
    $upload_dir  = __DIR__ . '/uploads/';

    // Verificação CSRF para todas as chamadas AJAX
    $raw_body   = file_get_contents('php://input');
    $json_body  = json_decode($raw_body, true) ?: [];
    $ajax_csrf  = $_POST['csrf_token'] ?? $json_body['csrf_token'] ?? '';
    if (!verifyCSRF($ajax_csrf)) {
        echo json_encode(['ok' => false, 'msg' => 'Erro de segurança. Recarregue a página.']);
        exit;
    }

    // ── AJAX: Upload fotos da sala ──
    if ($ajax_action === 'upload_sala' && isset($_FILES['fotos'])) {
        $sala_id = intval($_POST['sala_id'] ?? 0);
        if ($sala_id <= 0) { echo json_encode(['ok'=>false,'msg'=>'ID inválido']); exit; }

        $arquivos = normalizarArquivos($_FILES['fotos']);
        if (empty($arquivos)) { echo json_encode(['ok'=>false,'msg'=>'Nenhum arquivo válido recebido']); exit; }

        $salas_data = lerSalas($salas_json);
        $adicionadas = [];
        $errors = [];

        foreach ($arquivos as $file_entry) {
            $rel = processarUpload($file_entry, 'sala_' . $sala_id, $upload_dir);
            if ($rel) {
                foreach ($salas_data['salas'] as &$sala) {
                    if ($sala['id'] == $sala_id) {
                        if (!isset($sala['fotos'])) $sala['fotos'] = [];
                        $sala['fotos'][] = $rel;
                        if (empty($sala['imagem_principal'])) {
                            $sala['imagem_principal'] = $rel;
                        }
                        $adicionadas[] = $rel;
                        break;
                    }
                }
                unset($sala);
            } else {
                $errors[] = $file_entry['name'];
            }
        }

        if (!empty($adicionadas)) salvarJSON($salas_json, $salas_data);

        $msg = count($adicionadas) . ' foto(s) adicionada(s) com sucesso!';
        if (!empty($errors)) $msg .= ' Erro em: ' . implode(', ', $errors);
        echo json_encode(['ok' => !empty($adicionadas), 'msg' => $msg, 'paths' => $adicionadas, 'errors' => $errors]);
        exit;
    }

    // ── AJAX: Upload fotos da galeria home ──
    if ($ajax_action === 'upload_home' && isset($_FILES['fotos'])) {
        $arquivos = normalizarArquivos($_FILES['fotos']);
        if (empty($arquivos)) { echo json_encode(['ok'=>false,'msg'=>'Nenhum arquivo válido']); exit; }

        $galeria   = json_decode(@file_get_contents($galeria_json), true) ?: ['fotos' => []];
        $adicionadas = [];

        foreach ($arquivos as $file_entry) {
            $rel = processarUpload($file_entry, 'home', $upload_dir);
            if ($rel) {
                $galeria['fotos'][] = $rel;
                $adicionadas[] = $rel;
            }
        }

        if (!empty($adicionadas)) salvarJSON($galeria_json, $galeria);

        echo json_encode(['ok' => !empty($adicionadas), 'msg' => count($adicionadas) . ' foto(s) adicionada(s)!', 'paths' => $adicionadas]);
        exit;
    }

    // ── AJAX: Remover foto da sala ──
    if ($ajax_action === 'remove_foto_sala') {
        $data = $json_body;
        $sala_id   = intval($data['sala_id'] ?? 0);
        $foto_path = $data['foto_path'] ?? '';
        $salas_data = lerSalas($salas_json);
        foreach ($salas_data['salas'] as &$sala) {
            if ($sala['id'] == $sala_id) {
                $sala['fotos'] = array_values(array_filter($sala['fotos'] ?? [], fn($f) => $f !== $foto_path));
                if (($sala['imagem_principal'] ?? '') === $foto_path) {
                    $sala['imagem_principal'] = !empty($sala['fotos']) ? $sala['fotos'][0] : '';
                }
                break;
            }
        }
        unset($sala);
        $ok = salvarJSON($salas_json, $salas_data);
        echo json_encode(['ok' => $ok]);
        exit;
    }

    // ── AJAX: Definir foto principal da sala ──
    if ($ajax_action === 'set_main_sala') {
        $data = $json_body;
        $sala_id   = intval($data['sala_id'] ?? 0);
        $foto_path = $data['foto_path'] ?? '';
        $salas_data = lerSalas($salas_json);
        foreach ($salas_data['salas'] as &$sala) {
            if ($sala['id'] == $sala_id) { $sala['imagem_principal'] = $foto_path; break; }
        }
        unset($sala);
        $ok = salvarJSON($salas_json, $salas_data);
        echo json_encode(['ok' => $ok]);
        exit;
    }

    // ── AJAX: Remover foto da galeria home ──
    if ($ajax_action === 'remove_foto_home') {
        $data = $json_body;
        $foto_path = $data['foto_path'] ?? '';
        $galeria   = json_decode(@file_get_contents($galeria_json), true) ?: ['fotos' => []];
        $galeria['fotos'] = array_values(array_filter($galeria['fotos'], fn($f) => $f !== $foto_path));
        $ok = salvarJSON($galeria_json, $galeria);
        echo json_encode(['ok' => $ok]);
        exit;
    }

    // ── AJAX: GET/SAVE/DELETE PONTOS ESTRATÉGICOS ──
    if ($ajax_action === 'get_pontos') {
        ob_clean();
        $d = file_exists($pontos_json) ? (json_decode(file_get_contents($pontos_json),true) ?: ['pontos'=>[]]) : ['pontos'=>[]];
        echo json_encode($d); exit;
    }
    // Upload de fotos para ponto (múltiplas, via uploadSequencial do JS)
    if ($ajax_action === 'upload_foto_ponto') {
        $id   = intval($_POST['id'] ?? 0);
        $nome = trim($_POST['nome'] ?? '');
        $d    = file_exists($pontos_json) ? (json_decode(file_get_contents($pontos_json),true) ?: ['pontos'=>[]]) : ['pontos'=>[]];
        $paths = [];
        $files = normalizarArquivos($_FILES['fotos'] ?? []);
        $dir   = __DIR__ . '/uploads/diferenciais/';
        foreach ($files as $fe) {
            $rel = processarUpload($fe, 'ponto_'.$id, $dir, false);
            if ($rel) $paths[] = $rel;
        }
        if ($id > 0 && !empty($paths)) {
            foreach ($d['pontos'] as &$p) {
                if ($p['id'] == $id) {
                    if (!isset($p['fotos'])) $p['fotos'] = [];
                    $p['fotos'] = array_merge($p['fotos'], $paths);
                    break;
                }
            }
            unset($p);
        } elseif ($id == 0 && !empty($nome)) {
            $nid = !empty($d['pontos']) ? max(array_column($d['pontos'],'id'))+1 : 1;
            $d['pontos'][] = ['id'=>$nid,'nome'=>$nome,'fotos'=>$paths];
        }
        $ok = salvarJSON($pontos_json, $d);
        echo json_encode(['ok'=>$ok,'msg'=>$ok?'✅ '.count($paths).' foto(s)!':'❌ Erro','paths'=>$paths]); exit;
    }
    if ($ajax_action === 'save_ponto') {
        $d   = file_exists($pontos_json) ? (json_decode(file_get_contents($pontos_json),true) ?: ['pontos'=>[]]) : ['pontos'=>[]];
        $id  = intval($_POST['id'] ?? 0);
        $nome = trim($_POST['nome'] ?? '');
        if ($id > 0) {
            foreach ($d['pontos'] as &$p) { if ($p['id'] == $id) { if ($nome) $p['nome'] = $nome; break; } }
            unset($p);
        } else {
            $nid = !empty($d['pontos']) ? max(array_column($d['pontos'],'id'))+1 : 1;
            $d['pontos'][] = ['id'=>$nid,'nome'=>$nome,'fotos'=>[]];
        }
        $ok = salvarJSON($pontos_json, $d);
        echo json_encode(['ok'=>$ok,'msg'=>$ok?'✅ Ponto salvo!':'❌ Erro']); exit;
    }
    if ($ajax_action === 'delete_foto_ponto') {
        $data = $json_body;
        $id   = intval($data['id'] ?? 0);
        $foto = $data['foto'] ?? '';
        $d    = file_exists($pontos_json) ? (json_decode(file_get_contents($pontos_json),true) ?: ['pontos'=>[]]) : ['pontos'=>[]];
        foreach ($d['pontos'] as &$p) {
            if ($p['id'] == $id) { $p['fotos'] = array_values(array_filter($p['fotos']??[], fn($f)=>$f!==$foto)); break; }
        }
        unset($p);
        $ok = salvarJSON($pontos_json, $d);
        echo json_encode(['ok'=>$ok]); exit;
    }
    if ($ajax_action === 'delete_ponto') {
        $data = $json_body;
        $id   = intval($data['id'] ?? 0);
        $d    = file_exists($pontos_json) ? (json_decode(file_get_contents($pontos_json),true) ?: ['pontos'=>[]]) : ['pontos'=>[]];
        $d['pontos'] = array_values(array_filter($d['pontos'], fn($p) => $p['id'] != $id));
        $ok = salvarJSON($pontos_json, $d);
        echo json_encode(['ok'=>$ok]); exit;
    }

    // ── AJAX: GET/SAVE/DELETE CLIENTES ──
    if ($ajax_action === 'get_clientes') {
        ob_clean();
        $d = file_exists($clientes_json) ? (json_decode(file_get_contents($clientes_json),true) ?: ['clientes'=>[]]) : ['clientes'=>[]];
        echo json_encode($d); exit;
    }
    // Upload de fotos para cliente (múltiplas, via uploadSequencial do JS)
    if ($ajax_action === 'upload_foto_cliente') {
        $id   = intval($_POST['id'] ?? 0);
        $nome = trim($_POST['nome'] ?? '');
        $d    = file_exists($clientes_json) ? (json_decode(file_get_contents($clientes_json),true) ?: ['clientes'=>[]]) : ['clientes'=>[]];
        $paths = [];
        $files = normalizarArquivos($_FILES['fotos'] ?? []);
        $slug  = preg_replace('/[^a-z0-9_]/', '_', strtolower($nome ?: 'cli_'.$id));
        $dir   = __DIR__ . '/uploads/clientes/' . $slug . '/';
        foreach ($files as $fe) {
            $rel = processarUpload($fe, 'cli', $dir, false);
            if ($rel) $paths[] = $rel;
        }
        if ($id > 0 && !empty($paths)) {
            foreach ($d['clientes'] as &$c) {
                if ($c['id'] == $id) { if (!isset($c['fotos'])) $c['fotos']=[]; $c['fotos']=array_merge($c['fotos'],$paths); break; }
            }
            unset($c);
        } elseif ($id == 0 && !empty($nome)) {
            $nid = !empty($d['clientes']) ? max(array_column($d['clientes'],'id'))+1 : 1;
            $d['clientes'][] = ['id'=>$nid,'nome'=>$nome,'fotos'=>$paths,'ativo'=>true];
        }
        $ok = salvarJSON($clientes_json, $d);
        echo json_encode(['ok'=>$ok,'msg'=>$ok?'✅ '.count($paths).' foto(s)!':'❌ Erro','paths'=>$paths]); exit;
    }
    if ($ajax_action === 'save_cliente') {
        $d    = file_exists($clientes_json) ? (json_decode(file_get_contents($clientes_json),true) ?: ['clientes'=>[]]) : ['clientes'=>[]];
        $id   = intval($_POST['id'] ?? 0);
        $nome = trim($_POST['nome'] ?? '');
        $ativo = ($_POST['ativo'] ?? '1') === '1';
        if ($id > 0) {
            foreach ($d['clientes'] as &$c) {
                if ($c['id'] == $id) { if ($nome) $c['nome']=$nome; $c['ativo']=$ativo; break; }
            }
            unset($c);
        } else {
            $nid = !empty($d['clientes']) ? max(array_column($d['clientes'],'id'))+1 : 1;
            $d['clientes'][] = ['id'=>$nid,'nome'=>$nome,'fotos'=>[],'ativo'=>$ativo];
        }
        $ok = salvarJSON($clientes_json, $d);
        echo json_encode(['ok'=>$ok,'msg'=>$ok?'✅ Cliente salvo!':'❌ Erro']); exit;
    }
    if ($ajax_action === 'delete_cliente') {
        $data = $json_body;
        $id   = intval($data['id'] ?? 0);
        $d    = file_exists($clientes_json) ? (json_decode(file_get_contents($clientes_json),true) ?: ['clientes'=>[]]) : ['clientes'=>[]];
        $d['clientes'] = array_values(array_filter($d['clientes'], fn($c) => $c['id'] != $id));
        $ok = salvarJSON($clientes_json, $d);
        echo json_encode(['ok'=>$ok]); exit;
    }
    if ($ajax_action === 'delete_foto_cliente') {
        $data  = json_decode(file_get_contents('php://input'),true);
        $id    = intval($data['id'] ?? 0);
        $foto  = $data['foto'] ?? '';
        $d     = file_exists($clientes_json) ? (json_decode(file_get_contents($clientes_json),true) ?: ['clientes'=>[]]) : ['clientes'=>[]];
        foreach ($d['clientes'] as &$c) {
            if ($c['id'] == $id) {
                $c['fotos'] = array_values(array_filter($c['fotos'] ?? [], fn($f) => $f !== $foto));
                break;
            }
        }
        unset($c);
        $ok = salvarJSON($clientes_json, $d);
        echo json_encode(['ok'=>$ok]); exit;
    }
    if ($ajax_action === 'toggle_cliente') {
        $data = $json_body;
        $id   = intval($data['id'] ?? 0);
        $d    = file_exists($clientes_json) ? (json_decode(file_get_contents($clientes_json),true) ?: ['clientes'=>[]]) : ['clientes'=>[]];
        foreach ($d['clientes'] as &$c) {
            if ($c['id'] == $id) { $c['ativo'] = !($c['ativo'] ?? true); break; }
        }
        unset($c);
        $ok = salvarJSON($clientes_json, $d);
        echo json_encode(['ok'=>$ok]); exit;
    }

    // ── AJAX: Salvar URL do YouTube (vídeo da home) ──
    if ($ajax_action === 'save_youtube_url') {
        $youtube_url = trim($json_body['youtube_url'] ?? '');
        // Valida: aceita URL YouTube ou string vazia (remoção)
        $url_valida = empty($youtube_url) || preg_match(
            '/^https?:\/\/(www\.)?(youtube\.com\/(watch\?v=|embed\/|shorts\/)|youtu\.be\/)[a-zA-Z0-9_\-]{11}/',
            $youtube_url
        );
        if (!$url_valida) {
            echo json_encode(['ok' => false, 'msg' => '❌ URL do YouTube inválida.']); exit;
        }
        $galeria = json_decode(@file_get_contents($galeria_json), true) ?: ['fotos' => []];
        if (empty($youtube_url)) {
            unset($galeria['youtube_url']);
            $ok = salvarJSON($galeria_json, $galeria);
            echo json_encode(['ok' => $ok, 'msg' => $ok ? '✅ Vídeo removido!' : '❌ Erro ao salvar.']); exit;
        }
        $galeria['youtube_url'] = $youtube_url;
        $ok = salvarJSON($galeria_json, $galeria);
        echo json_encode(['ok' => $ok, 'msg' => $ok ? '✅ URL do YouTube salva!' : '❌ Erro ao salvar.']); exit;
    }

    echo json_encode(['ok'=>false,'msg'=>'Ação desconhecida']);
    exit;
}

// =========================================================
// AÇÕES POST normais (formulários)
// =========================================================
$message = '';

if ($is_logged_in && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCSRF($_POST['csrf_token'] ?? '')) {
        $message = '<div class="msg-error">❌ Erro de segurança (token inválido). Recarregue a página.</div>';
        goto endActions;
    }
    $action = $_POST['action'] ?? '';
    $salas_data = lerSalas($salas_json);

    // ── ADICIONAR SALA ──
    if ($action === 'add_room') {
        $novo_id = !empty($salas_data['salas']) ? max(array_column($salas_data['salas'], 'id')) + 1 : 1;
        $salas_data['salas'][] = [
            'id'              => $novo_id,
            'nome'            => trim($_POST['nome'] ?? 'Nova Sala'),
            'andar'           => $_POST['andar'] ?? 'TÉRREO',
            'tamanho'         => intval($_POST['tamanho'] ?? 0),
            'descricao'       => trim($_POST['descricao'] ?? ''),
            'imagem_principal'=> '',
            'fotos'           => [],
            'sobre'           => trim($_POST['sobre'] ?? 'Descrição detalhada sobre esta sala ou loja.'),
            'caracteristicas' => [
                'Piso em porcelanato de alta qualidade',
                'Iluminação LED embutida',
                'Tomadas e pontos de rede distribuídos',
                'Forro de gesso com isolamento acústico',
                'Banheiro privativo',
            ],
            'specs'           => [
                ['icon' => '📏', 'titulo' => 'Tamanho',    'valor' => intval($_POST['tamanho'] ?? 0) . ' m²'],
                ['icon' => '🏢', 'titulo' => 'Andar',      'valor' => $_POST['andar'] ?? 'TÉRREO'],
                ['icon' => '🚪', 'titulo' => 'Tipo',       'valor' => 'Comercial'],
                ['icon' => '💡', 'titulo' => 'Elétrica',   'valor' => 'Bifásico'],
            ],
            'facilidades'     => [
                ['icon' => '🅿️',  'valor' => 'Estacionamento'],
                ['icon' => '🔒', 'valor' => 'Segurança 24h'],
                ['icon' => '♿', 'valor' => 'Acessibilidade'],
                ['icon' => '🌐', 'valor' => 'Fibra óptica'],
            ],
            'alugada'         => false,
            'inativa'         => false,
            'data_aluguel'    => null,
            'motivo_inativa'  => '',
        ];
        salvarJSON($salas_json, $salas_data);
        $message = '<div class="msg-success">✅ Sala adicionada! Agora edite e adicione fotos.</div>';
    }

    // ── EDITAR SALA ──
    if ($action === 'edit_room') {
        $sala_id = intval($_POST['sala_id']);
        foreach ($salas_data['salas'] as &$sala) {
            if ($sala['id'] == $sala_id) {
                $sala['nome']      = trim($_POST['nome'] ?? $sala['nome']);
                $sala['andar']     = $_POST['andar'] ?? $sala['andar'];
                $sala['tamanho']   = intval($_POST['tamanho'] ?? $sala['tamanho']);
                $sala['descricao'] = trim($_POST['descricao'] ?? $sala['descricao']);
                $sala['sobre']     = trim($_POST['sobre'] ?? ($sala['sobre'] ?? ''));
                // Specs
                $specs = [];
                if (isset($_POST['spec_icon'])) {
                    for ($i = 0; $i < count($_POST['spec_icon']); $i++) {
                        if (!empty(trim($_POST['spec_titulo'][$i] ?? ''))) {
                            $specs[] = ['icon'=>trim($_POST['spec_icon'][$i]),'titulo'=>trim($_POST['spec_titulo'][$i]),'valor'=>trim($_POST['spec_valor'][$i] ?? '')];
                        }
                    }
                }
                $sala['specs'] = $specs;
                // Características
                $cars = [];
                foreach ($_POST['caracteristicas'] ?? [] as $c) { if (!empty(trim($c))) $cars[] = trim($c); }
                $sala['caracteristicas'] = $cars;
                // Facilidades
                $facs = [];
                if (isset($_POST['fac_icon'])) {
                    for ($i = 0; $i < count($_POST['fac_icon']); $i++) {
                        if (!empty(trim($_POST['fac_valor'][$i] ?? ''))) {
                            $facs[] = ['icon'=>trim($_POST['fac_icon'][$i]),'valor'=>trim($_POST['fac_valor'][$i])];
                        }
                    }
                }
                $sala['facilidades'] = $facs;
                // URL do vídeo YouTube da sala (opcional)
                $yt = trim($_POST['youtube_url'] ?? '');
                $sala['youtube_url'] = $yt;
                break;
            }
        }
        unset($sala);
        salvarJSON($salas_json, $salas_data);
        $message = '<div class="msg-success">✅ Sala atualizada!</div>';
    }

    // ── TOGGLE ALUGUEL ──
    if ($action === 'toggle_aluguel') {
        $sala_id = intval($_POST['sala_id']);
        foreach ($salas_data['salas'] as &$sala) {
            if ($sala['id'] == $sala_id) {
                $sala['alugada']      = !($sala['alugada'] ?? false);
                $sala['data_aluguel'] = $sala['alugada'] ? date('Y-m-d H:i:s') : null;
                if ($sala['alugada']) $sala['inativa'] = false; // alugada cancela inativa
                break;
            }
        }
        unset($sala);
        salvarJSON($salas_json, $salas_data);
        $message = '<div class="msg-success">✅ Status de aluguel atualizado!</div>';
    }

    // ── TOGGLE DESTAQUE ──
    if ($action === 'toggle_destaque') {
        $sala_id = intval($_POST['sala_id']);
        foreach ($salas_data['salas'] as &$sala) {
            if ($sala['id'] == $sala_id) {
                $sala['destaque'] = !($sala['destaque'] ?? false);
                break;
            }
        }
        unset($sala);
        salvarJSON($salas_json, $salas_data);
        $message = '<div class="msg-success">✅ Status de destaque atualizado!</div>';
    }

    // ── TOGGLE INATIVA ──
    if ($action === 'toggle_inativa') {
        $sala_id = intval($_POST['sala_id']);
        $motivo  = trim($_POST['motivo_inativa'] ?? '');
        foreach ($salas_data['salas'] as &$sala) {
            if ($sala['id'] == $sala_id) {
                $sala['inativa'] = !($sala['inativa'] ?? false);
                $sala['motivo_inativa'] = $sala['inativa'] ? $motivo : '';
                if ($sala['inativa']) $sala['alugada'] = false; // inativa cancela alugada
                break;
            }
        }
        unset($sala);
        salvarJSON($salas_json, $salas_data);
        $label = '';
        foreach ($salas_data['salas'] as $s) { if ($s['id'] == intval($_POST['sala_id'])) { $label = $s['inativa'] ? 'Inativada' : 'Reativada'; break; } }
        $message = '<div class="msg-success">✅ Sala ' . $label . ' com sucesso!</div>';
    }

    // ── EXCLUIR SALA ──
    if ($action === 'delete_room') {
        $sala_id = intval($_POST['sala_id']);
        $salas_data['salas'] = array_values(array_filter($salas_data['salas'], fn($s) => $s['id'] != $sala_id));
        salvarJSON($salas_json, $salas_data);
        $message = '<div class="msg-success">✅ Sala excluída!</div>';
    }

    // ── MANAGE PHOTOS (set_main / delete_photo via form) ──
    if ($action === 'manage_photos') {
        $sala_id    = intval($_POST['sala_id']);
        $sub_action = $_POST['sub_action'] ?? '';
        foreach ($salas_data['salas'] as &$sala) {
            if ($sala['id'] == $sala_id) {
                if ($sub_action === 'set_main') {
                    $sala['imagem_principal'] = $_POST['photo_path'];
                } elseif ($sub_action === 'delete_photo') {
                    $r = $_POST['photo_path'];
                    $sala['fotos'] = array_values(array_filter($sala['fotos'] ?? [], fn($f) => $f !== $r));
                    if (($sala['imagem_principal'] ?? '') === $r) {
                        $sala['imagem_principal'] = !empty($sala['fotos']) ? $sala['fotos'][0] : '';
                    }
                }
                break;
            }
        }
        unset($sala);
        salvarJSON($salas_json, $salas_data);
        $message = '<div class="msg-success">✅ Foto atualizada!</div>';
    }

    // ── DELETE FOTO GALERIA HOME ──
    if ($action === 'delete_home_photo') {
        $galeria = json_decode(@file_get_contents($galeria_json), true) ?: ['fotos' => []];
        $galeria['fotos'] = array_values(array_filter($galeria['fotos'], fn($f) => $f !== $_POST['photo_path']));
        salvarJSON($galeria_json, $galeria);
        $message = '<div class="msg-success">✅ Foto removida da galeria!</div>';
    }

    // ── ALTERAR CREDENCIAIS ──
    if ($action === 'change_credentials') {
        $new_user = trim($_POST['new_user'] ?? '');
        $cur_pass = $_POST['current_pass'] ?? '';
        $new_pass = $_POST['new_pass'] ?? '';
        $cnf_pass = $_POST['confirm_pass'] ?? '';
        if (!password_verify($cur_pass, $admin_hash)) {
            $message = '<div class="msg-error">❌ Senha atual incorreta.</div>';
            logAudit($audit_file, 'credentials_change_failed', 'senha_atual_errada');
        } elseif (!empty($new_pass) && $new_pass !== $cnf_pass) {
            $message = '<div class="msg-error">❌ As novas senhas não coincidem.</div>';
        } elseif (!empty($new_pass) && strlen($new_pass) < 8) {
            $message = '<div class="msg-error">❌ A nova senha deve ter no mínimo 8 caracteres.</div>';
        } else {
            $up = ['user'=>!empty($new_user)?$new_user:$admin_user,'hash'=>!empty($new_pass)?password_hash($new_pass,PASSWORD_BCRYPT):$admin_hash];
            file_put_contents($cred_file, json_encode($up));
            @chmod($cred_file, 0600);
            // Regenera token de sessão após mudança de credenciais
            session_regenerate_id(true);
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            $message = '<div class="msg-success">✅ Credenciais atualizadas com sucesso!</div>';
            logAudit($audit_file, 'credentials_changed', 'user=' . ($new_user ?: $admin_user));
            $admin_user = $up['user'];
            $admin_hash = $up['hash'];
        }
    }

    endActions:
}

// Recuperar mensagem de redirect GET
if (empty($message) && isset($_GET['msg'])) {
    $m = htmlspecialchars(urldecode($_GET['msg']));
    $message = strpos($m,'✅') !== false ? '<div class="msg-success">'.$m.'</div>' : '<div class="msg-error">'.$m.'</div>';
}

$tab_ativa   = $_GET['tab'] ?? 'salas';
$salas_data  = lerSalas($salas_json);
$salas       = $salas_data['salas'] ?? [];
$galeria_data= json_decode(@file_get_contents($galeria_json), true) ?: ['fotos' => []];
$json_ok     = is_writable($salas_json);
$uploads_ok  = is_dir(__DIR__.'/uploads') ? is_writable(__DIR__.'/uploads') : is_writable(__DIR__);
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="<?= getCSRFToken() ?>">
    <title>Painel ADM - Prédio Logos</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f0f2f5;color:#333;min-height:100vh}

        /* LOGIN */
        .login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#1A1F3A 0%,#2C3E50 100%);padding:20px}
        .login-box{background:#fff;border-radius:16px;padding:44px 40px;box-shadow:0 20px 60px rgba(0,0,0,.3);max-width:380px;width:100%}
        .login-box h1{font-size:26px;color:#1A1F3A;margin-bottom:6px}
        .login-box p{color:#888;margin-bottom:28px;font-size:14px}
        .form-group{margin-bottom:18px}
        .form-group label{display:block;font-size:12px;font-weight:700;color:#555;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px}
        .form-group input,.form-group textarea,.form-group select{width:100%;padding:11px 14px;border:2px solid #e8e8e8;border-radius:8px;font-size:14px;transition:border-color .2s;font-family:inherit}
        .form-group input:focus,.form-group textarea:focus,.form-group select:focus{outline:none;border-color:#1e88e5}
        .form-group textarea{min-height:80px;resize:vertical}
        .btn-login{width:100%;padding:13px;background:#1A1F3A;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:700;cursor:pointer;transition:background .2s}
        .btn-login:hover{background:#1e88e5}
        .login-error{background:#fde8e8;color:#c0392b;padding:10px 14px;border-radius:8px;font-size:13px;margin-bottom:18px}

        /* ADMIN WRAP */
        .admin-wrap{max-width:1100px;margin:0 auto;padding:24px 16px 60px}
        .admin-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:22px;flex-wrap:wrap;gap:12px;background:#fff;padding:18px 22px;border-radius:12px;box-shadow:0 2px 10px rgba(0,0,0,.07)}
        .admin-header h1{font-size:20px;color:#1A1F3A}
        .header-btns{display:flex;gap:8px;flex-wrap:wrap}
        .btn-site{background:#1e88e5;color:#fff;padding:9px 18px;border:none;border-radius:7px;font-weight:700;cursor:pointer;text-decoration:none;font-size:13px;display:inline-block}
        .btn-salas{background:#4caf50;color:#fff;padding:9px 18px;border:none;border-radius:7px;font-weight:700;cursor:pointer;text-decoration:none;font-size:13px;display:inline-block}
        .btn-logout{background:#f44336;color:#fff;padding:9px 18px;border:none;border-radius:7px;font-weight:700;cursor:pointer;text-decoration:none;font-size:13px;display:inline-block}

        /* MENSAGENS */
        .msg-success{background:#d4edda;color:#155724;padding:12px 18px;border-radius:8px;margin-bottom:18px;font-size:14px;font-weight:600;animation:fadeIn .3s}
        .msg-error{background:#f8d7da;color:#721c24;padding:12px 18px;border-radius:8px;margin-bottom:18px;font-size:14px;font-weight:600}
        .msg-warn{background:#fff3cd;color:#856404;padding:12px 18px;border-radius:8px;margin-bottom:18px;font-size:13px}
        @keyframes fadeIn{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}

        /* TABS */
        .tabs{display:flex;gap:6px;margin-bottom:20px;flex-wrap:wrap}
        .tab-btn{padding:10px 20px;background:#fff;border:2px solid #e8e8e8;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;color:#555;transition:all .2s}
        .tab-btn:hover{border-color:#1e88e5;color:#1e88e5}
        .tab-btn.active{background:#1e88e5;color:#fff;border-color:#1e88e5}
        .tab-panel{display:none}
        .tab-panel.active{display:block}

        /* ACCORDION */
        .rooms-list{display:flex;flex-direction:column;gap:12px}
        .room-item{background:#fff;border-radius:12px;box-shadow:0 2px 10px rgba(0,0,0,.07);overflow:hidden}
        .room-header{padding:16px 20px;cursor:pointer;display:flex;justify-content:space-between;align-items:center;font-weight:600;color:#1A1F3A;user-select:none;transition:background .2s}
        .room-header:hover,.room-header.open{background:#f5f7fa}
        .room-header.open{border-bottom:2px solid #e8e8e8}
        .room-arrow{font-size:12px;color:#888;transition:transform .3s;flex-shrink:0;margin-left:10px}
        .room-header.open .room-arrow{transform:rotate(180deg)}
        .room-body{display:none;padding:22px}
        .room-body.open{display:block}

        /* STATUS BADGES */
        .status-disponivel{color:#4caf50;font-size:12px;font-weight:700}
        .status-alugada{color:#f44336;font-size:12px;font-weight:700}
        .status-inativa{color:#9E9E9E;font-size:12px;font-weight:700}

        /* FORM */
        .form-section{margin-bottom:26px}
        .form-section h3{font-size:13px;font-weight:800;color:#1A1F3A;text-transform:uppercase;letter-spacing:.5px;border-bottom:2px solid #1e88e5;padding-bottom:7px;margin-bottom:14px}
        .form-row{display:grid;grid-template-columns:1fr 1fr;gap:14px}
        @media(max-width:600px){.form-row{grid-template-columns:1fr}}

        /* ====== UPLOAD AJAX ====== */
        .upload-zone {
            border: 2px dashed #b3d4f7;
            border-radius: 12px;
            background: #f0f7ff;
            padding: 20px;
            text-align: center;
            cursor: pointer;
            transition: border-color .2s, background .2s;
            position: relative;
            margin-top: 14px;
        }
        .upload-zone:hover, .upload-zone.drag-over {
            border-color: #1e88e5;
            background: #e3f2fd;
        }
        .upload-zone input[type=file] {
            position: absolute;
            inset: 0;
            width: 100%;
            height: 100%;
            opacity: 0;
            cursor: pointer;
        }
        .upload-zone-label {
            pointer-events: none;
        }
        .upload-zone-icon { font-size: 32px; margin-bottom: 8px; }
        .upload-zone-text { font-size: 14px; font-weight: 700; color: #1A1F3A; margin-bottom: 4px; }
        .upload-zone-sub  { font-size: 12px; color: #888; }

        /* Progress bar */
        .upload-progress-wrap {
            display: none;
            margin-top: 12px;
            background: #e8e8e8;
            border-radius: 8px;
            overflow: hidden;
            height: 10px;
        }
        .upload-progress-bar {
            height: 100%;
            background: #1e88e5;
            width: 0%;
            transition: width .3s;
            border-radius: 8px;
        }
        .upload-status {
            margin-top: 10px;
            font-size: 13px;
            font-weight: 600;
            min-height: 20px;
        }
        .upload-status.ok { color: #2e7d32; }
        .upload-status.err { color: #c62828; }
        .upload-status.loading { color: #1e88e5; }

        /* FOTOS */
        .photo-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:10px;margin-top:12px}
        .photo-card{border:2px solid #e8e8e8;border-radius:10px;overflow:hidden;position:relative;transition:border-color .2s}
        .photo-card.main-photo{border-color:#4caf50}
        .photo-card img{width:100%;height:85px;object-fit:cover;display:block}
        .photo-badge{position:absolute;top:4px;left:4px;background:#4caf50;color:#fff;font-size:9px;font-weight:800;padding:2px 6px;border-radius:8px;pointer-events:none}
        .photo-actions{padding:5px;display:flex;gap:4px}
        .btn-photo-sm{flex:1;padding:5px 3px;font-size:10px;border:none;border-radius:5px;cursor:pointer;font-weight:700}
        .btn-set-main{background:#1e88e5;color:#fff}
        .btn-del-photo{background:#f44336;color:#fff}

        /* DINÂMICOS */
        .dynamic-row{display:grid;gap:8px;margin-bottom:8px;align-items:center}
        .spec-row{grid-template-columns:44px 1fr 1fr 36px}
        .car-row{grid-template-columns:1fr 36px}
        .fac-row{grid-template-columns:44px 1fr 36px}
        .btn-remove{background:#f44336;color:#fff;border:none;border-radius:6px;padding:7px 10px;cursor:pointer;font-size:14px;font-weight:700}
        .btn-add-item{background:#1e88e5;color:#fff;border:none;border-radius:6px;padding:8px 14px;cursor:pointer;font-size:12px;font-weight:700;margin-top:6px}

        /* AÇÕES */
        .room-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:20px;padding-top:16px;border-top:1px solid #e8e8e8}
        .btn-save{background:#1e88e5;color:#fff;padding:11px 22px;border:none;border-radius:7px;cursor:pointer;font-weight:700;font-size:13px}
        .btn-aluguel-livre{background:#4caf50;color:#fff;padding:11px 22px;border:none;border-radius:7px;cursor:pointer;font-weight:700;font-size:13px}
        .btn-aluguel-ocu{background:#ff9800;color:#fff;padding:11px 22px;border:none;border-radius:7px;cursor:pointer;font-weight:700;font-size:13px}
        .btn-inativa{background:#757575;color:#fff;padding:11px 22px;border:none;border-radius:7px;cursor:pointer;font-weight:700;font-size:13px}
        .btn-ativa{background:#4caf50;color:#fff;padding:11px 22px;border:none;border-radius:7px;cursor:pointer;font-weight:700;font-size:13px}
        .btn-delete{background:#f44336;color:#fff;padding:11px 22px;border:none;border-radius:7px;cursor:pointer;font-weight:700;font-size:13px}
        .btn-add-sala{background:#4caf50;color:#fff;padding:11px 22px;border:none;border-radius:8px;cursor:pointer;font-weight:700;font-size:14px;margin-bottom:18px}

        /* INATIVA box */
        .inativa-box{background:#f9f9f9;border:1px solid #e0e0e0;border-radius:8px;padding:14px;margin-top:8px}
        .inativa-box label{font-size:12px;font-weight:700;color:#555;text-transform:uppercase;letter-spacing:.5px;display:block;margin-bottom:6px}
        .inativa-box input{width:100%;padding:10px;border:2px solid #e8e8e8;border-radius:7px;font-size:14px}
        .inativa-banner{background:#f3f3f3;border-left:4px solid #9E9E9E;padding:10px 14px;border-radius:0 8px 8px 0;font-size:13px;color:#666;margin-bottom:12px}

        /* MODAL */
        .modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:9000;align-items:center;justify-content:center}
        .modal-overlay.active{display:flex}
        .modal-box{background:#fff;border-radius:16px;padding:30px;max-width:500px;width:90%;box-shadow:0 20px 60px rgba(0,0,0,.3);max-height:90vh;overflow-y:auto}
        .modal-box h2{font-size:20px;color:#1A1F3A;margin-bottom:18px}
        .modal-actions{display:flex;gap:10px;margin-top:18px;flex-wrap:wrap}

        /* GALERIA HOME */
        .card-section{background:#fff;border-radius:12px;box-shadow:0 2px 10px rgba(0,0,0,.07);padding:22px;margin-bottom:22px}
        .card-section h3{font-size:16px;font-weight:800;color:#1A1F3A;margin-bottom:6px}
        .card-section .desc{font-size:13px;color:#888;margin-bottom:16px}
        .home-photo-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:10px;margin-top:14px}
        .home-photo-card{border:1px solid #e8e8e8;border-radius:10px;overflow:hidden;position:relative}
        .home-photo-card img{width:100%;height:80px;object-fit:cover;display:block}
        .btn-remove-home{width:100%;padding:6px;background:#f44336;color:#fff;border:none;font-size:11px;cursor:pointer;font-weight:700}
        .home-photo-card.adding{opacity:.4;pointer-events:none}

        /* CRED */
        .cred-card{background:#fff;border-radius:12px;padding:26px;box-shadow:0 2px 10px rgba(0,0,0,.07);max-width:500px}
        /* Novos botões admin */
        .btn-primary-admin{padding:11px 20px;background:#1e88e5;color:#fff;border:none;border-radius:8px;cursor:pointer;font-weight:700;font-size:13px;transition:background .2s}
        .btn-primary-admin:hover{background:#1565c0}
        .btn-acao{padding:8px 14px;background:#f0f4f9;color:#333;border:1px solid #d0d9e6;border-radius:7px;cursor:pointer;font-size:12px;font-weight:600;transition:all .15s}
        .btn-acao:hover{background:#e0eaf8;border-color:#1e88e5;color:#1e88e5}
        .btn-danger{background:#fff0f0!important;color:#c0392b!important;border-color:#f5c6c6!important}
        .btn-danger:hover{background:#c0392b!important;color:#fff!important;border-color:#c0392b!important}
        .ponto-admin-row{background:#f7f9fc;border-radius:10px;padding:14px;border:1px solid #e8eef5}
        /* Stats panel */
        .admin-stats-wrap{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px}
        .admin-stat-card{flex:1;min-width:80px;background:#f0f4f9;border-radius:10px;padding:12px 10px;text-align:center;border:1px solid #e0e8f0}
        .admin-stat-card.stat-green{background:#e8faf0;border-color:#c3e6d0}
        .admin-stat-card.stat-red{background:#fef0f0;border-color:#f5c6c6}
        .admin-stat-card.stat-gray{background:#f5f5f5;border-color:#ddd}
        .admin-stat-card.stat-amber{background:#fff8e8;border-color:#f5e0a0}
        .stat-val{font-size:22px;font-weight:800;color:#1A1F3A}
        .stat-lbl{font-size:11px;color:#888;font-weight:600;margin-top:2px}
        .admin-por-andar{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px}
        .andar-stat{background:#f7f9fc;border:1px solid #e0e8f0;border-radius:8px;padding:8px 12px;font-size:12px;display:flex;gap:8px;align-items:center}
        .andar-stat strong{color:#1A1F3A;font-weight:700}
        .as-disp{color:#1a8a4a;font-weight:600}
        .as-alug{color:#c0392b;font-weight:600}
        .as-inat{color:#999;font-weight:600}
        /* Item admin card — pontos e clientes */
        .item-admin-card{background:#f7f9fc;border-radius:12px;padding:16px;border:1px solid #e8eef5;margin-bottom:14px}
        .item-admin-header{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:12px}
        .fotos-existentes{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:10px;min-height:20px}
        .foto-thumb{position:relative;width:80px;height:64px;border-radius:8px;overflow:hidden;background:#e0e8f0}
        .foto-thumb img{width:100%;height:100%;object-fit:cover;display:block}
        .foto-thumb button{position:absolute;top:2px;right:2px;background:rgba(0,0,0,0.65);color:#fff;border:none;border-radius:50%;width:20px;height:20px;cursor:pointer;font-size:11px;line-height:1;display:flex;align-items:center;justify-content:center}
        .sem-fotos{font-size:11px;color:#aaa;padding:4px 0}
        .badge-status{font-size:11px;padding:2px 9px;border-radius:20px;font-weight:600}
        /* Upload zone mini */
        .upload-zone-mini{position:relative;border:2px dashed #c8d6e5;border-radius:8px;padding:11px 14px;cursor:pointer;background:#fff;transition:all .2s;display:flex;align-items:center;gap:8px;font-size:13px;color:#555}
        .upload-zone-mini:hover{border-color:#1e88e5;background:#f0f6fe;color:#1e88e5}
        .upload-zone-mini input[type=file]{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%}
        /* Barra de progresso mini */
        .mini-progress-wrap{display:none;background:#e0eaf5;border-radius:999px;height:6px;margin-top:6px;overflow:hidden}
        .mini-progress-bar{height:100%;background:linear-gradient(90deg,#1e88e5,#1565c0);width:0%;border-radius:999px;transition:width .25s}
        .mini-status{font-size:12px;min-height:16px;margin-top:4px;color:#555}
        .mini-status.ok{color:#1a8a4a;font-weight:600}
        .mini-status.err{color:#c0392b;font-weight:600}
    </style>
</head>
<body>

<?php if (!$is_logged_in): ?>
<div class="login-wrap">
    <div class="login-box">
        <h1>🏢 Painel ADM</h1>
        <p>Prédio Logos — Área Restrita</p>
        <?php if (isset($_GET['timeout'])): ?>
            <div class="login-error">Sessão expirada por inatividade. Faça login novamente.</div>
        <?php elseif (!empty($login_error)): ?>
            <div class="login-error"><?= htmlspecialchars($login_error) ?></div>
        <?php endif; ?>
        <form method="POST" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?= getCSRFToken() ?>">
            <div class="form-group"><label>Usuário</label><input type="text" name="username" autocomplete="username" required></div>
            <div class="form-group"><label>Senha</label><input type="password" name="password" placeholder="••••••" autocomplete="current-password" required></div>
            <button type="submit" name="login" class="btn-login">Entrar</button>
        </form>
    </div>
</div>
<?php else: ?>

<div class="admin-wrap">
    <div class="admin-header">
        <h1>🏢 Painel Administrativo</h1>
        <div class="header-btns">
            <a href="index.html" class="btn-site">← Voltar ao Site</a>
            <a href="salas.html" class="btn-salas">Ver Salas</a>
            <a href="?logout=1" class="btn-logout">Sair</a>
        </div>
    </div>

    <?php if (!$json_ok): ?><div class="msg-warn">⚠️ <strong>salas.json</strong> sem permissão de escrita. Execute: <code>chmod 666 salas.json</code></div><?php endif; ?>
    <?php if (!$uploads_ok): ?><div class="msg-warn">⚠️ Pasta <strong>uploads/</strong> não gravável. Execute: <code>chmod 755 uploads/</code></div><?php endif; ?>

    <!-- Mensagem global (toast) -->
    <div id="toast-global" style="display:none;position:fixed;top:20px;right:20px;z-index:9999;min-width:280px;max-width:400px;background:#2e7d32;color:#fff;padding:14px 20px;border-radius:10px;box-shadow:0 6px 24px rgba(0,0,0,.2);font-size:14px;font-weight:600;animation:fadeIn .3s"></div>

    <?php if ($message): echo $message; endif; ?>

    <div class="tabs">
        <button class="tab-btn <?= $tab_ativa==='salas'?'active':'' ?>" onclick="mudarAba('salas',this)">🏠 Gerenciar Salas</button>
        <button class="tab-btn <?= $tab_ativa==='galeria'?'active':'' ?>" onclick="mudarAba('galeria',this)">🖼️ Fotos do Prédio</button>
        <button class="tab-btn <?= $tab_ativa==='video'?'active':'' ?>" onclick="mudarAba('video',this)">🎬 Vídeo da Home</button>
        <button class="tab-btn <?= $tab_ativa==='pontos'?'active':'' ?>" onclick="mudarAba('pontos',this)">📍 Pontos Estratégicos</button>
        <button class="tab-btn <?= $tab_ativa==='clientes'?'active':'' ?>" onclick="mudarAba('clientes',this)">🤝 Clientes</button>
        <button class="tab-btn <?= $tab_ativa==='credenciais'?'active':'' ?>" onclick="mudarAba('credenciais',this)">🔐 Segurança</button>
    </div>

    <!-- ===== TAB SALAS ===== -->
    <div id="tab-salas" class="tab-panel <?= $tab_ativa==='salas'?'active':'' ?>">
        <!-- PAINEL DE ESTATÍSTICAS -->
        <?php
        $andares = ['SUBSOLO','TÉRREO','PRIMEIRO ANDAR','SEGUNDO ANDAR'];
        $stats_geral = ['total'=>0,'disponiveis'=>0,'alugadas'=>0,'inativas'=>0,'destaque'=>0];
        $stats_andar = [];
        foreach ($salas as $s) {
            $a = strtoupper($s['andar'] ?? 'TÉRREO');
            if (!isset($stats_andar[$a])) $stats_andar[$a] = ['total'=>0,'disponiveis'=>0,'alugadas'=>0,'inativas'=>0];
            $stats_andar[$a]['total']++;
            $stats_geral['total']++;
            if ($s['inativa'] ?? false) { $stats_geral['inativas']++; $stats_andar[$a]['inativas']++; }
            elseif ($s['alugada'] ?? false) { $stats_geral['alugadas']++; $stats_andar[$a]['alugadas']++; }
            else { $stats_geral['disponiveis']++; $stats_andar[$a]['disponiveis']++; }
            if ($s['destaque'] ?? false) $stats_geral['destaque']++;
        }
        ?>
        <div class="admin-stats-wrap">
            <div class="admin-stat-card">
                <div class="stat-val"><?= $stats_geral['total'] ?></div>
                <div class="stat-lbl">Total</div>
            </div>
            <div class="admin-stat-card stat-green">
                <div class="stat-val"><?= $stats_geral['disponiveis'] ?></div>
                <div class="stat-lbl">Disponíveis</div>
            </div>
            <div class="admin-stat-card stat-red">
                <div class="stat-val"><?= $stats_geral['alugadas'] ?></div>
                <div class="stat-lbl">Alugadas</div>
            </div>
            <div class="admin-stat-card stat-gray">
                <div class="stat-val"><?= $stats_geral['inativas'] ?></div>
                <div class="stat-lbl">Inativas</div>
            </div>
            <div class="admin-stat-card stat-amber">
                <div class="stat-val"><?= $stats_geral['destaque'] ?></div>
                <div class="stat-lbl">Destaque</div>
            </div>
        </div>
        <!-- Por andar -->
        <?php if (!empty($stats_andar)): ?>
        <div class="admin-por-andar">
            <?php foreach ($stats_andar as $andar => $st): ?>
            <div class="andar-stat">
                <strong><?= ucwords(strtolower(htmlspecialchars($andar))) ?></strong>
                <span class="as-disp"><?= $st['disponiveis'] ?> disp.</span>
                <span class="as-alug"><?= $st['alugadas'] ?> alug.</span>
                <span class="as-inat"><?= $st['inativas'] ?> inat.</span>
            </div>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>

        <button class="btn-add-sala" onclick="document.getElementById('modal-add').classList.add('active')">+ Adicionar Nova Sala</button>

        <div class="rooms-list">
        <?php foreach ($salas as $sala):
            $is_alugada = $sala['alugada'] ?? false;
            $is_inativa = $sala['inativa'] ?? false;
            if ($is_alugada) $status_html = '<span class="status-alugada">● ALUGADA</span>';
            elseif ($is_inativa) $status_html = '<span class="status-inativa">⏸ INATIVA</span>';
            else $status_html = '<span class="status-disponivel">● Disponível</span>';
        ?>
        <div class="room-item" id="room-<?= $sala['id'] ?>">
            <div class="room-header" onclick="toggleRoom(this)">
                <span>
                    <strong><?= htmlspecialchars($sala['nome']) ?></strong>
                    &nbsp;—&nbsp;<?= htmlspecialchars($sala['andar']) ?>&nbsp;·&nbsp;<?= $sala['tamanho'] ?>m²
                    &nbsp;<?= $status_html ?>
                </span>
                <span class="room-arrow">▼</span>
            </div>
            <div class="room-body">

                <?php if ($is_inativa): ?>
                <div class="inativa-banner">
                    ⏸ <strong>Sala Inativa</strong>
                    <?= !empty($sala['motivo_inativa']) ? '— Motivo: ' . htmlspecialchars($sala['motivo_inativa']) : '' ?>
                </div>
                <?php endif; ?>

                <!-- ==== UPLOAD FOTOS (AJAX, múltiplas) ==== -->
                <div class="form-section">
                    <h3>📸 Fotos da Sala</h3>

                    <!-- Fotos existentes -->
                    <div class="photo-grid" id="photo-grid-<?= $sala['id'] ?>">
                    <?php foreach ($sala['fotos'] ?? [] as $foto): ?>
                        <div class="photo-card <?= $sala['imagem_principal']===$foto?'main-photo':'' ?>" data-foto="<?= htmlspecialchars($foto) ?>">
                            <?php if ($sala['imagem_principal']===$foto): ?><span class="photo-badge">PRINCIPAL</span><?php endif; ?>
                            <img src="<?= htmlspecialchars($foto) ?>" alt="" onerror="this.src='fotos_predio/foto_predio_1.jpg'">
                            <div class="photo-actions">
                                <button type="button" class="btn-photo-sm btn-set-main"
                                    onclick="setMain(<?= $sala['id'] ?>,'<?= addslashes($foto) ?>', this)">Principal</button>
                                <button type="button" class="btn-photo-sm btn-del-photo"
                                    onclick="removerFoto(<?= $sala['id'] ?>,'<?= addslashes($foto) ?>', this)">✕</button>
                            </div>
                        </div>
                    <?php endforeach; ?>
                    </div>

                    <!-- Upload zone AJAX -->
                    <div class="upload-zone" id="uz-<?= $sala['id'] ?>">
                        <input type="file" name="fotos" accept="image/jpeg,image/png,image/webp,image/gif"
                            multiple
                            onchange="uploadFotosSala(<?= $sala['id'] ?>, this)">
                        <div class="upload-zone-label">
                            <div class="upload-zone-icon">📤</div>
                            <div class="upload-zone-text">Clique ou arraste fotos aqui</div>
                            <div class="upload-zone-sub">Somente fotos • JPG, PNG, WEBP, GIF</div>
                        </div>
                    </div>
                    <div class="upload-progress-wrap" id="prog-wrap-<?= $sala['id'] ?>">
                        <div class="upload-progress-bar" id="prog-<?= $sala['id'] ?>"></div>
                    </div>
                    <div class="upload-status" id="upload-status-<?= $sala['id'] ?>"></div>
                </div>

                <!-- ==== EDITAR INFOS ==== -->
                <form method="POST">
                    <input type="hidden" name="action" value="edit_room">
                    <input type="hidden" name="sala_id" value="<?= $sala['id'] ?>">

                    <div class="form-section">
                        <h3>📋 Informações Básicas</h3>
                        <div class="form-row">
                            <div class="form-group"><label>Nome</label><input type="text" name="nome" value="<?= htmlspecialchars($sala['nome']) ?>" required></div>
                            <div class="form-group">
                                <label>Andar</label>
                                <select name="andar" required>
                                    <?php foreach(['SUBSOLO'=>'Subsolo','TÉRREO'=>'Térreo','PRIMEIRO ANDAR'=>'Primeiro Andar','SEGUNDO ANDAR'=>'Segundo Andar'] as $v=>$l): ?>
                                    <option value="<?=$v?>" <?=strtoupper($sala['andar'])===$v?'selected':''?>><?=$l?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                        </div>
                        <div class="form-row">
                            <div class="form-group"><label>Tamanho (m²)</label><input type="number" name="tamanho" value="<?= $sala['tamanho'] ?>" required min="1"></div>
                        </div>
                        <div class="form-group"><label>Descrição Curta</label><textarea name="descricao"><?= htmlspecialchars($sala['descricao']) ?></textarea></div>
                        <div class="form-group"><label>Sobre esta Sala</label><textarea name="sobre"><?= htmlspecialchars($sala['sobre'] ?? '') ?></textarea></div>
                        <div class="form-group">
                            <label>🎬 Vídeo da Sala — URL do YouTube (opcional)</label>
                            <input type="url" name="youtube_url"
                                value="<?= htmlspecialchars($sala['youtube_url'] ?? '') ?>"
                                placeholder="https://www.youtube.com/watch?v=... ou https://youtu.be/...">
                            <small style="color:#888;font-size:11px;margin-top:4px;display:block">
                                Deixe vazio para não exibir vídeo. Cole a URL do YouTube do vídeo desta sala (pode ser não listado).
                            </small>
                        </div>
                    </div>

                    <div class="form-section">
                        <h3>📏 Especificações</h3>
                        <div id="specs_<?= $sala['id'] ?>">
                        <?php foreach($sala['specs']??[] as $s): ?>
                            <div class="dynamic-row spec-row">
                                <input type="text" name="spec_icon[]" value="<?= htmlspecialchars($s['icon']??'📋') ?>" style="text-align:center" maxlength="3">
                                <input type="text" name="spec_titulo[]" value="<?= htmlspecialchars($s['titulo']??'') ?>">
                                <input type="text" name="spec_valor[]" value="<?= htmlspecialchars($s['valor']??'') ?>">
                                <button type="button" class="btn-remove" onclick="this.parentElement.remove()">✕</button>
                            </div>
                        <?php endforeach; ?>
                        </div>
                        <button type="button" class="btn-add-item" onclick="addSpec(<?= $sala['id'] ?>)">+ Spec</button>
                    </div>

                    <div class="form-section">
                        <h3>✅ Características</h3>
                        <div id="cars_<?= $sala['id'] ?>">
                        <?php foreach($sala['caracteristicas']??[] as $c): ?>
                            <div class="dynamic-row car-row">
                                <input type="text" name="caracteristicas[]" value="<?= htmlspecialchars($c) ?>">
                                <button type="button" class="btn-remove" onclick="this.parentElement.remove()">✕</button>
                            </div>
                        <?php endforeach; ?>
                        </div>
                        <button type="button" class="btn-add-item" onclick="addCar(<?= $sala['id'] ?>)">+ Característica</button>
                    </div>

                    <div class="form-section">
                        <h3>🏢 Facilidades</h3>
                        <div id="facs_<?= $sala['id'] ?>">
                        <?php foreach($sala['facilidades']??[] as $f): ?>
                            <div class="dynamic-row fac-row">
                                <input type="text" name="fac_icon[]" value="<?= htmlspecialchars($f['icon']??'🏢') ?>" style="text-align:center" maxlength="3">
                                <input type="text" name="fac_valor[]" value="<?= htmlspecialchars($f['valor']??'') ?>">
                                <button type="button" class="btn-remove" onclick="this.parentElement.remove()">✕</button>
                            </div>
                        <?php endforeach; ?>
                        </div>
                        <button type="button" class="btn-add-item" onclick="addFac(<?= $sala['id'] ?>)">+ Facilidade</button>
                    </div>

                    <div class="room-actions">
                        <button type="submit" class="btn-save">💾 Salvar Alterações</button>
                    </div>
                </form>

                <!-- TOGGLE ALUGUEL, INATIVA, EXCLUIR — forms próprios -->
                <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px">
                    <form method="POST" style="margin:0">
                        <input type="hidden" name="action" value="toggle_aluguel">
                        <input type="hidden" name="sala_id" value="<?= $sala['id'] ?>">
                        <button type="submit" class="<?= $is_alugada?'btn-aluguel-ocu':'btn-aluguel-livre' ?>">
                            <?= $is_alugada?'🔓 Marcar Disponível':'🔒 Marcar Alugada' ?>
                        </button>
                    </form>

                    <!-- DESTAQUE -->
                    <form method="POST" style="margin:0">
                        <input type="hidden" name="action" value="toggle_destaque">
                        <input type="hidden" name="sala_id" value="<?= $sala['id'] ?>">
                        <button type="submit" class="<?= ($sala['destaque']??false) ? 'btn-aluguel-ocu' : 'btn-save' ?>"
                            style="<?= ($sala['destaque']??false) ? 'background:#FFB300;color:#1A1F3A' : 'background:#795548' ?>">
                            <?= ($sala['destaque']??false) ? '★ Em Destaque (clique para remover)' : '☆ Marcar como Destaque' ?>
                        </button>
                    </form>

                    <!-- INATIVA: abre caixa com motivo -->
                    <?php if (!$is_inativa): ?>
                    <button type="button" class="btn-inativa"
                        onclick="document.getElementById('inativa-box-<?= $sala['id'] ?>').style.display='block';this.style.display='none'">
                        ⏸ Inativar Sala
                    </button>
                    <div id="inativa-box-<?= $sala['id'] ?>" class="inativa-box" style="display:none;width:100%;margin-top:8px">
                        <form method="POST" style="margin:0">
                            <input type="hidden" name="action" value="toggle_inativa">
                            <input type="hidden" name="sala_id" value="<?= $sala['id'] ?>">
                            <label>Motivo (opcional — ex: Em negociação, Em manutenção)</label>
                            <input type="text" name="motivo_inativa" placeholder="Ex: Em manutenção" style="margin-bottom:10px">
                            <div style="display:flex;gap:8px;margin-top:10px">
                                <button type="submit" class="btn-inativa">⏸ Confirmar Inativação</button>
                                <button type="button" class="btn-save"
                                    onclick="document.getElementById('inativa-box-<?= $sala['id'] ?>').style.display='none';document.querySelector('#room-<?= $sala['id'] ?> .btn-inativa').style.display='inline-block'">
                                    Cancelar
                                </button>
                            </div>
                        </form>
                    </div>
                    <?php else: ?>
                    <form method="POST" style="margin:0">
                        <input type="hidden" name="action" value="toggle_inativa">
                        <input type="hidden" name="sala_id" value="<?= $sala['id'] ?>">
                        <button type="submit" class="btn-ativa">▶ Reativar Sala</button>
                    </form>
                    <?php endif; ?>

                    <form method="POST" style="margin:0" onsubmit="return confirm('EXCLUIR esta sala? Não pode ser desfeito!')">
                        <input type="hidden" name="action" value="delete_room">
                        <input type="hidden" name="sala_id" value="<?= $sala['id'] ?>">
                        <button type="submit" class="btn-delete">🗑️ Excluir</button>
                    </form>
                </div>

            </div><!-- /room-body -->
        </div><!-- /room-item -->
        <?php endforeach; ?>

        <?php if (empty($salas)): ?>
        <div style="text-align:center;padding:40px;color:#999;background:#fff;border-radius:12px">
            <p>Nenhuma sala cadastrada. Clique em "Adicionar Nova Sala".</p>
        </div>
        <?php endif; ?>
        </div>
    </div>

    <!-- ===== TAB GALERIA HOME ===== -->
    <div id="tab-galeria" class="tab-panel <?= $tab_ativa==='galeria'?'active':'' ?>">
        <div class="card-section">
            <h3>🖼️ Galeria da Página Principal</h3>
            <p class="desc">Fotos das miniaturas selecionáveis abaixo do vídeo na página inicial.</p>

            <!-- Upload AJAX múltiplas fotos -->
            <div class="upload-zone" id="uz-home">
                <input type="file" name="fotos" accept="image/jpeg,image/png,image/webp,image/gif"
                    multiple onchange="uploadFotosHome(this)">
                <div class="upload-zone-label">
                    <div class="upload-zone-icon">🖼️</div>
                    <div class="upload-zone-text">Clique ou arraste fotos aqui</div>
                    <div class="upload-zone-sub">Múltiplas fotos • JPG, PNG, WEBP</div>
                </div>
            </div>
            <div class="upload-progress-wrap" id="prog-wrap-home">
                <div class="upload-progress-bar" id="prog-home"></div>
            </div>
            <div class="upload-status" id="upload-status-home"></div>

            <div class="home-photo-grid" id="home-photo-grid">
                <?php foreach ($galeria_data['fotos'] ?? [] as $foto): ?>
                <div class="home-photo-card" data-foto="<?= htmlspecialchars($foto) ?>">
                    <img src="<?= htmlspecialchars($foto) ?>" alt="" onerror="this.src='fotos_predio/foto_predio_1.jpg'">
                    <button type="button" class="btn-remove-home"
                        onclick="removerFotoHome('<?= addslashes($foto) ?>', this)">✕ Remover</button>
                </div>
                <?php endforeach; ?>
                <?php if (empty($galeria_data['fotos'])): ?>
                <p style="color:#999;font-size:13px;grid-column:1/-1">Nenhuma foto. Adicione acima.</p>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- ===== TAB GALERIA: renomeia para clareza ===== -->
    <!-- (a aba de galeria existente agora é "Fotos do Prédio") -->

    <!-- ===== TAB VÍDEO DA HOME ===== -->
    <div id="tab-video" class="tab-panel <?= $tab_ativa==='video'?'active':'' ?>">
        <div class="card-section">
            <h3>🎬 Vídeo da Página Inicial (YouTube)</h3>
            <p class="desc">
                Cole aqui a URL de um vídeo do YouTube para usar como fundo animado na home.
                O vídeo toca automaticamente sem som e em loop — sem consumir espaço no servidor.
            </p>

            <?php $yt_url_atual = $galeria_data['youtube_url'] ?? ''; ?>

            <?php if ($yt_url_atual): ?>
            <div style="background:#e8f5e9;border:1px solid #a5d6a7;border-radius:10px;padding:14px 18px;margin-bottom:16px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
                <div>
                    <strong style="color:#1a8a4a;font-size:13px">✅ Vídeo configurado:</strong>
                    <a href="<?= htmlspecialchars($yt_url_atual) ?>" target="_blank"
                       style="font-size:12px;color:#1e88e5;word-break:break-all"><?= htmlspecialchars($yt_url_atual) ?></a>
                </div>
                <button type="button" onclick="removerYoutubeUrl()"
                    style="background:#f44336;color:#fff;border:none;border-radius:7px;padding:8px 16px;cursor:pointer;font-size:13px;font-weight:700;white-space:nowrap">
                    ✕ Remover
                </button>
            </div>
            <?php else: ?>
            <div style="background:#fff8e1;border:1px solid #ffe082;border-radius:10px;padding:12px 16px;margin-bottom:16px;font-size:13px;color:#795548">
                ⚠️ Nenhum vídeo configurado. O site mostrará o vídeo padrão local (se existir).
            </div>
            <?php endif; ?>

            <div style="display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap">
                <div style="flex:1;min-width:200px">
                    <label style="display:block;font-size:12px;font-weight:700;color:#555;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px">
                        URL do YouTube
                    </label>
                    <input type="url" id="youtube-url-input"
                        placeholder="https://www.youtube.com/watch?v=XXXXXXXXXXX"
                        value="<?= htmlspecialchars($yt_url_atual) ?>"
                        style="width:100%;padding:11px 14px;border:2px solid #e8e8e8;border-radius:8px;font-size:14px;font-family:inherit">
                </div>
                <button type="button" onclick="salvarYoutubeUrl()"
                    style="background:#1e88e5;color:#fff;border:none;border-radius:8px;padding:11px 22px;cursor:pointer;font-weight:700;font-size:13px;white-space:nowrap">
                    💾 Salvar
                </button>
            </div>
            <div id="youtube-url-status" style="margin-top:8px;font-size:13px;font-weight:600;min-height:18px"></div>

            <div style="margin-top:20px;background:#f5f5f5;border-radius:10px;padding:14px 16px;font-size:13px;color:#666">
                <strong>Como usar:</strong><br>
                1. Abra o YouTube e encontre o vídeo desejado<br>
                2. Copie a URL da barra de endereços (ex: <code>https://www.youtube.com/watch?v=ABC123</code>)<br>
                3. Cole no campo acima e clique em Salvar<br>
                <br>
                <strong>Dica:</strong> Para que o vídeo toque automático, ele deve estar configurado como <em>público</em> ou <em>não listado</em> no YouTube.
            </div>
        </div>
    </div>

    <!-- ===== TAB PONTOS ESTRATÉGICOS ===== -->
    <div id="tab-pontos" class="tab-panel <?= $tab_ativa==='pontos'?'active':'' ?>">
        <div class="card-section">
            <h3>📍 Pontos Estratégicos</h3>
            <p class="desc">Cards de localização na seção "Diferenciais". Adicione várias fotos em cada ponto — no site as fotos passam automaticamente como um slideshow.</p>

            <?php
            $pontos_data = file_exists($pontos_json)
                ? (json_decode(file_get_contents($pontos_json),true) ?: ['pontos'=>[]])
                : ['pontos'=>[]];
            foreach ($pontos_data['pontos'] as $pt):
            $fts = $pt['fotos'] ?? (isset($pt['imagem']) && $pt['imagem'] ? [$pt['imagem']] : []);
            ?>
            <div class="item-admin-card" id="pr-<?= $pt['id'] ?>">
                <div class="item-admin-header">
                    <span style="font-weight:700;font-size:14px;color:#1A1F3A"><?= htmlspecialchars($pt['nome']) ?></span>
                    <div style="display:flex;gap:6px">
                        <button type="button" class="btn-acao" onclick="editarNomePonto(<?= $pt['id'] ?>, '<?= addslashes($pt['nome']) ?>')">✏️ Nome</button>
                        <button type="button" class="btn-acao btn-danger" onclick="deletarPonto(<?= $pt['id'] ?>)">🗑️</button>
                    </div>
                </div>
                <!-- Fotos existentes -->
                <div class="fotos-existentes" id="fotos-pt-<?= $pt['id'] ?>">
                    <?php foreach ($fts as $f): ?>
                    <div class="foto-thumb">
                        <img src="<?= htmlspecialchars($f) ?>" alt="">
                        <button type="button" onclick="removerFotoPonto(<?= $pt['id'] ?>, '<?= addslashes($f) ?>', this)">✕</button>
                    </div>
                    <?php endforeach; ?>
                    <?php if (empty($fts)): ?><p class="sem-fotos">Nenhuma foto ainda</p><?php endif; ?>
                </div>
                <!-- Zone de upload com barra de progresso -->
                <div class="upload-zone-mini" id="uz-pt-<?= $pt['id'] ?>">
                    <input type="file" accept="image/jpeg,image/png,image/webp,image/gif" multiple
                        onchange="uploadFotosPonto(<?= $pt['id'] ?>, '<?= addslashes($pt['nome']) ?>', this)">
                    <span>📷 Adicionar Fotos (várias de uma vez)</span>
                </div>
                <div class="mini-progress-wrap" id="prog-wrap-pt-<?= $pt['id'] ?>">
                    <div class="mini-progress-bar" id="prog-pt-<?= $pt['id'] ?>"></div>
                </div>
                <div class="mini-status" id="status-pt-<?= $pt['id'] ?>"></div>
            </div>
            <?php endforeach; ?>

            <div style="margin-top:16px;display:flex;gap:10px;flex-wrap:wrap">
                <button type="button" class="btn-primary-admin" onclick="mostrarFormNovoPonto()">➕ Adicionar Ponto</button>
            </div>
            <div id="form-novo-ponto" style="display:none;margin-top:16px;background:#f7f9fc;border-radius:12px;padding:16px;border:1px solid #e8eef5">
                <h4 style="margin-bottom:10px;color:#1A1F3A">Novo Ponto</h4>
                <input type="text" id="np-nome" style="width:100%;padding:10px;border:1.5px solid #ddd;border-radius:8px;margin-bottom:10px;font-size:14px" placeholder="Ex: Próximo ao Shopping">
                <div style="display:flex;gap:8px">
                    <button type="button" class="btn-primary-admin" onclick="salvarNovoPonto()">✅ Criar</button>
                    <button type="button" class="btn-acao" onclick="document.getElementById('form-novo-ponto').style.display='none'">Cancelar</button>
                </div>
                <div id="np-status" style="margin-top:8px;font-size:13px"></div>
            </div>
        </div>
    </div>

    <!-- ===== TAB CLIENTES ===== -->
    <div id="tab-clientes" class="tab-panel <?= $tab_ativa==='clientes'?'active':'' ?>">
        <div class="card-section">
            <h3>🤝 Clientes do Prédio</h3>
            <p class="desc">Adicione várias fotos de cada cliente — no site as fotos passam como slideshow automático.</p>

            <?php
            $cli_data = file_exists($clientes_json)
                ? (json_decode(file_get_contents($clientes_json),true) ?: ['clientes'=>[]])
                : ['clientes'=>[]];
            foreach ($cli_data['clientes'] as $cli):
            $fotos_cli = $cli['fotos'] ?? [];
            ?>
            <div class="item-admin-card" id="cli-card-<?= $cli['id'] ?>">
                <div class="item-admin-header">
                    <div style="display:flex;align-items:center;gap:10px">
                        <span style="font-weight:700;font-size:15px;color:#1A1F3A"><?= htmlspecialchars($cli['nome']) ?></span>
                        <span class="badge-status" style="background:<?= ($cli['ativo']??true)?'#e8faf0':'#f0f0f0' ?>;color:<?= ($cli['ativo']??true)?'#1a8a4a':'#888' ?>">
                            <?= ($cli['ativo']??true) ? '● Ativo' : '○ Inativo' ?>
                        </span>
                    </div>
                    <div style="display:flex;gap:6px;flex-wrap:wrap">
                        <button type="button" class="btn-acao" onclick="editarNomeCliente(<?= $cli['id'] ?>, '<?= addslashes($cli['nome']) ?>')">✏️ Nome</button>
                        <button type="button" class="btn-acao" onclick="toggleCliente(<?= $cli['id'] ?>)">
                            <?= ($cli['ativo']??true) ? 'Inativar' : 'Ativar' ?>
                        </button>
                        <button type="button" class="btn-acao btn-danger" onclick="deletarCliente(<?= $cli['id'] ?>)">🗑️ Remover</button>
                    </div>
                </div>
                <!-- Fotos existentes -->
                <div class="fotos-existentes" id="fotos-cli-<?= $cli['id'] ?>">
                    <?php foreach ($fotos_cli as $f): ?>
                    <div class="foto-thumb">
                        <img src="<?= htmlspecialchars($f) ?>" alt="">
                        <button type="button" onclick="removerFotoCli(<?= $cli['id'] ?>, '<?= addslashes($f) ?>', this)">✕</button>
                    </div>
                    <?php endforeach; ?>
                    <?php if (empty($fotos_cli)): ?><p class="sem-fotos">Nenhuma foto ainda</p><?php endif; ?>
                </div>
                <!-- Zone de upload com progresso -->
                <div class="upload-zone-mini" id="uz-cli-<?= $cli['id'] ?>">
                    <input type="file" accept="image/jpeg,image/png,image/webp,image/gif" multiple
                        onchange="uploadFotosCli(<?= $cli['id'] ?>, '<?= addslashes($cli['nome']) ?>', this)">
                    <span>📷 Adicionar Fotos (várias de uma vez)</span>
                </div>
                <div class="mini-progress-wrap" id="prog-wrap-cli-<?= $cli['id'] ?>">
                    <div class="mini-progress-bar" id="prog-cli-<?= $cli['id'] ?>"></div>
                </div>
                <div class="mini-status" id="status-cli-<?= $cli['id'] ?>"></div>
            </div>
            <?php endforeach; ?>

            <div style="margin-top:16px">
                <button type="button" class="btn-primary-admin" onclick="mostrarFormNovoCliente()">➕ Adicionar Cliente</button>
            </div>
            <div id="form-novo-cli" style="display:none;margin-top:14px;background:#f7f9fc;border-radius:12px;padding:16px;border:1px solid #e8eef5">
                <h4 style="margin-bottom:10px;color:#1A1F3A">Novo Cliente</h4>
                <input type="text" id="nc-nome" style="width:100%;padding:10px;border:1.5px solid #ddd;border-radius:8px;margin-bottom:10px;font-size:14px" placeholder="Ex: Equatorial Energia">
                <div style="display:flex;gap:8px">
                    <button type="button" class="btn-primary-admin" onclick="salvarNovoCliente()">✅ Criar</button>
                    <button type="button" class="btn-acao" onclick="document.getElementById('form-novo-cli').style.display='none'">Cancelar</button>
                </div>
                <div id="nc-status" style="margin-top:8px;font-size:13px"></div>
            </div>
        </div>
    </div>


    <!-- ===== TAB CREDENCIAIS ===== -->
    <div id="tab-credenciais" class="tab-panel <?= $tab_ativa==='credenciais'?'active':'' ?>">
        <div class="cred-card">
            <h3 style="font-size:17px;color:#1A1F3A;margin-bottom:16px">🔐 Alterar Credenciais</h3>
            <form method="POST">
                <input type="hidden" name="action" value="change_credentials">
                <div class="form-group"><label>Novo Usuário (atual: <?= htmlspecialchars($admin_user) ?>)</label><input type="text" name="new_user" placeholder="Deixe em branco para manter" autocomplete="off"></div>
                <div class="form-group"><label>Senha Atual *</label><input type="password" name="current_pass" required></div>
                <div class="form-group"><label>Nova Senha</label><input type="password" name="new_pass" placeholder="Deixe em branco para manter"></div>
                <div class="form-group"><label>Confirmar Nova Senha</label><input type="password" name="confirm_pass"></div>
                <button type="submit" class="btn-save">Salvar</button>
            </form>
        </div>
    </div>

</div><!-- /admin-wrap -->

<!-- MODAL ADICIONAR SALA -->
<div class="modal-overlay" id="modal-add">
    <div class="modal-box">
        <h2>➕ Adicionar Nova Sala</h2>
        <form method="POST">
            <input type="hidden" name="action" value="add_room">
            <div class="form-group"><label>Nome</label><input type="text" name="nome" placeholder="Ex: Sala 101" required></div>
            <div class="form-row">
                <div class="form-group">
                    <label>Andar</label>
                    <select name="andar" required>
                        <option value="SUBSOLO">Subsolo</option>
                        <option value="TÉRREO" selected>Térreo</option>
                        <option value="PRIMEIRO ANDAR">Primeiro Andar</option>
                        <option value="SEGUNDO ANDAR">Segundo Andar</option>
                    </select>
                </div>
                <div class="form-group"><label>Tamanho (m²)</label><input type="number" name="tamanho" placeholder="35" required min="1"></div>
            </div>
            <div class="form-group"><label>Descrição</label><textarea name="descricao" required></textarea></div>
            <div class="form-group"><label>Sobre esta Sala</label><textarea name="sobre"></textarea></div>
            <div class="modal-actions">
                <button type="submit" class="btn-save">✅ Adicionar</button>
                <button type="button" class="btn-logout" onclick="document.getElementById('modal-add').classList.remove('active')">Cancelar</button>
            </div>
        </form>
    </div>
</div>
<?php endif; ?>

<script>
// ===========================
// SEGURANÇA — CSRF Token global
// ===========================
var CSRF_TOKEN = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';

// Injeta automaticamente csrf_token em todos os formulários POST
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('form[method="POST"], form[method="post"]').forEach(function(f) {
        if (!f.querySelector('input[name="csrf_token"]')) {
            var inp = document.createElement('input');
            inp.type = 'hidden';
            inp.name = 'csrf_token';
            inp.value = CSRF_TOKEN;
            f.appendChild(inp);
        }
    });
});

// Helper: fetch seguro com CSRF (JSON)
function secureFetch(url, body) {
    return fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(Object.assign({ csrf_token: CSRF_TOKEN }, body))
    }).then(function(r) { return r.json(); });
}

// ===========================
// TABS
// ===========================
function mudarAba(nome, btn) {
    document.querySelectorAll('.tab-panel').forEach(function(p){ p.classList.remove('active'); });
    document.querySelectorAll('.tab-btn').forEach(function(b){ b.classList.remove('active'); });
    document.getElementById('tab-' + nome).classList.add('active');
    btn.classList.add('active');
}

// ===========================
// ACCORDION
// ===========================
function toggleRoom(header) {
    var body = header.nextElementSibling;
    var aberto = header.classList.contains('open');
    document.querySelectorAll('.room-header.open').forEach(function(h){
        h.classList.remove('open');
        h.nextElementSibling.classList.remove('open');
    });
    if (!aberto) { header.classList.add('open'); body.classList.add('open'); }
}

// ===========================
// TOAST
// ===========================
function showToast(msg, ok) {
    var t = document.getElementById('toast-global');
    if (!t) return;
    t.textContent = msg;
    t.style.background = ok ? '#2e7d32' : '#c62828';
    t.style.display = 'block';
    t.style.animation = 'none';
    void t.offsetWidth; // reflow
    t.style.animation = 'fadeIn .3s';
    clearTimeout(t._timer);
    t._timer = setTimeout(function(){ t.style.display = 'none'; }, 4000);
}

// ===========================
// COMPRESSÃO DE IMAGENS (client-side)
// Reduz fotos de câmera (~10MB) para ~300-500KB antes do upload
// Muito mais rápido no mobile sem perda visual perceptível
// ===========================
var COMPRESS_MAX_PX  = 1280;   // px máx — equilibrio entre qualidade e velocidade no celular
var COMPRESS_QUALITY = 0.78;   // qualidade JPEG/WebP — suficiente para web, arquivo menor

// === WAKE LOCK: mantém tela acesa durante o upload ===
var _wakeLock = null;
function solicitarWakeLock() {
    if ('wakeLock' in navigator) {
        navigator.wakeLock.request('screen')
            .then(function(wl) { _wakeLock = wl; })
            .catch(function() {}); // silencia se não suportado
    }
}
function liberarWakeLock() {
    if (_wakeLock) { try { _wakeLock.release(); } catch(e) {} _wakeLock = null; }
}
// Reativa wake lock ao voltar para a aba
document.addEventListener('visibilitychange', function() {
    if (document.visibilityState === 'visible' && _wakeLock === null) {
        // Se houver upload em andamento, reativa
        var temUploadAtivo = document.querySelector('.upload-status.loading');
        if (temUploadAtivo) solicitarWakeLock();
    }
});

// === COMPRESSÃO ===
function comprimirArquivo(file) {
    return new Promise(function(resolve) {
        // Vídeos e GIFs: sem compressão
        if (!file.type || !file.type.startsWith('image/') || file.type === 'image/gif') {
            resolve(file); return;
        }
        // Arquivo já pequeno (< 250KB): não precisa comprimir, vai rápido
        if (file.size < 256000) { resolve(file); return; }
        try {
            var reader = new FileReader();
            reader.onerror = function() { resolve(file); };
            reader.onload = function(e) {
                var img = new Image();
                img.onerror = function() { resolve(file); };
                img.onload = function() {
                    try {
                        var w = img.naturalWidth  || img.width  || 1;
                        var h = img.naturalHeight || img.height || 1;
                        var ratio = Math.min(COMPRESS_MAX_PX / w, COMPRESS_MAX_PX / h, 1);
                        var nw = Math.max(1, Math.round(w * ratio));
                        var nh = Math.max(1, Math.round(h * ratio));

                        var canvas = document.createElement('canvas');
                        canvas.width = nw; canvas.height = nh;
                        var ctx = canvas.getContext('2d');
                        if (!ctx) { resolve(file); return; }
                        ctx.imageSmoothingEnabled = true;
                        ctx.imageSmoothingQuality = 'high';
                        ctx.drawImage(img, 0, 0, nw, nh);

                        // Tenta WebP (mais compacto), cai em JPEG
                        var supWebP = canvas.toDataURL('image/webp').indexOf('data:image/webp') === 0;
                        var outType = supWebP ? 'image/webp' : 'image/jpeg';
                        var outExt  = supWebP ? '.webp' : '.jpg';

                        canvas.toBlob(function(blob) {
                            if (!blob || blob.size === 0) { resolve(file); return; }
                            var nome = file.name.replace(/\.[^.]+$/, outExt);
                            resolve(new File([blob], nome, {type: outType, lastModified: Date.now()}));
                        }, outType, COMPRESS_QUALITY);
                    } catch(err) { resolve(file); }
                };
                img.src = e.target.result;
            };
            reader.readAsDataURL(file);
        } catch(err) { resolve(file); }
    });
}

// Comprime todos os arquivos em paralelo
function comprimirTodos(files, statusEl) {
    var arr = Array.from(files);
    var qtdImagens = arr.filter(function(f){ return f.type && f.type.startsWith('image/') && f.type !== 'image/gif'; }).length;
    if (qtdImagens > 0 && statusEl) {
        statusEl.className = 'upload-status loading';
        statusEl.textContent = 'Otimizando ' + qtdImagens + ' foto(s)... aguarde';
    }
    return Promise.all(arr.map(comprimirArquivo));
}

// === UPLOAD SEQUENCIAL COM WAKE LOCK ===
// Cada arquivo é enviado separadamente para maior resiliência
// (funciona mesmo se o celular sair da tela durante o upload de um arquivo)
function uploadSequencial(url, formDataBase, arquivos, onProgresso, onCadaArquivo, onFinalizado) {
    var enviados = [];
    var erros = [];
    var idx = 0;

    function enviarProximo() {
        if (idx >= arquivos.length) {
            onFinalizado(enviados, erros);
            return;
        }
        var arquivo = arquivos[idx];
        idx++;

        var formData = new FormData();
        for (var par of formDataBase.entries()) { formData.append(par[0], par[1]); }
        formData.append('csrf_token', CSRF_TOKEN);
        formData.append('fotos[]', arquivo);

        var xhr = new XMLHttpRequest();
        xhr.open('POST', url);

        xhr.upload.addEventListener('progress', function(ev) {
            if (ev.lengthComputable) {
                var pct = Math.round(((idx - 1 + ev.loaded / ev.total) / arquivos.length) * 100);
                onProgresso(Math.min(pct, 99));
            }
        });

        xhr.addEventListener('load', function() {
            try {
                var r = JSON.parse(xhr.responseText);
                if (r.ok && r.paths) {
                    enviados = enviados.concat(r.paths);
                    onCadaArquivo(r.paths, idx, arquivos.length);
                } else {
                    erros.push(arquivo.name + (r.msg ? ' (' + r.msg + ')' : ''));
                }
            } catch(ex) {
                // Resposta não é JSON — ainda assim o arquivo pode ter sido salvo
                // Ignora e tenta o próximo
                erros.push(arquivo.name + ' (resposta inválida)');
            }
            enviarProximo();
        });

        xhr.addEventListener('error', function() {
            erros.push(arquivo.name + ' (falha de rede)');
            enviarProximo(); // tenta o próximo mesmo assim
        });

        xhr.addEventListener('abort', function() {
            erros.push(arquivo.name + ' (cancelado)');
            enviarProximo();
        });

        xhr.send(formData);
    }

    enviarProximo();
}

// ===========================
// COMPRESSÃO DE IMAGENS (client-side)
// ===========================
// UPLOAD AJAX — SALA
// ===========================
function uploadFotosSala(salaId, input) {
    var files = input.files;
    if (!files || files.length === 0) return;

    var progWrap = document.getElementById('prog-wrap-' + salaId);
    var progBar  = document.getElementById('prog-' + salaId);
    var statusEl = document.getElementById('upload-status-' + salaId);
    var grid     = document.getElementById('photo-grid-' + salaId);

    progWrap.style.display = 'block';
    progBar.style.width = '3%';
    solicitarWakeLock(); // mantém tela acesa

    comprimirTodos(files, statusEl).then(function(arquivosOtimizados) {
        var origMB = Array.from(files).reduce(function(s,f){ return s+f.size; },0)/1048576;
        var novoMB = arquivosOtimizados.reduce(function(s,f){ return s+f.size; },0)/1048576;
        var economia = origMB > novoMB + 0.1 ? ' (era ' + origMB.toFixed(1) + 'MB)' : '';

        statusEl.className = 'upload-status loading';
        statusEl.textContent = 'Enviando ' + arquivosOtimizados.length + ' arquivo(s)... pode sair do navegador';
        progBar.style.width = '8%';

        // FormData base com o sala_id
        var base = new FormData();
        base.append('sala_id', salaId);

        uploadSequencial(
            'admin.php?ajax=upload_sala',
            base,
            arquivosOtimizados,
            // onProgresso
            function(pct) {
                progBar.style.width = pct + '%';
            },
            // onCadaArquivo (atualiza o grid imediatamente)
            function(paths, atual, total) {
                statusEl.textContent = 'Enviado ' + atual + ' de ' + total + '...';
                if (grid) paths.forEach(function(p) { adicionarFotoGrid(grid, salaId, p); });
            },
            // onFinalizado
            function(enviados, erros) {
                progBar.style.width = '100%';
                liberarWakeLock();
                var msg = '';
                if (enviados.length > 0) {
                    msg = '✅ ' + enviados.length + ' foto(s) adicionada(s) — ' + novoMB.toFixed(1) + 'MB' + economia;
                    statusEl.className = 'upload-status ok';
                    showToast(msg, true);
                }
                if (erros.length > 0) {
                    msg += (msg ? ' | ' : '') + '⚠️ ' + erros.length + ' erro(s)';
                    statusEl.className = enviados.length > 0 ? 'upload-status ok' : 'upload-status err';
                    console.warn('Erros de upload:', erros);
                }
                statusEl.textContent = msg || '✅ Concluído!';
                setTimeout(function(){ progWrap.style.display='none'; progBar.style.width='0%'; }, 3000);
                input.value = '';
            }
        );
    }).catch(function(err) {
        liberarWakeLock();
        console.error('Erro compressão:', err);
        statusEl.className = 'upload-status err';
        statusEl.textContent = '❌ Erro ao processar imagens. Tente novamente.';
        progWrap.style.display = 'none';
        input.value = '';
    });
}

// ===========================
// UPLOAD AJAX — GALERIA HOME
// ===========================
function uploadFotosHome(input) {
    var files = input.files;
    if (!files || files.length === 0) return;

    var progWrap = document.getElementById('prog-wrap-home');
    var progBar  = document.getElementById('prog-home');
    var statusEl = document.getElementById('upload-status-home');
    var grid     = document.getElementById('home-photo-grid');

    progWrap.style.display = 'block';
    progBar.style.width = '3%';
    solicitarWakeLock();

    comprimirTodos(files, statusEl).then(function(arquivosOtimizados) {
        var origMB = Array.from(files).reduce(function(s,f){ return s+f.size; },0)/1048576;
        var novoMB = arquivosOtimizados.reduce(function(s,f){ return s+f.size; },0)/1048576;

        statusEl.className = 'upload-status loading';
        statusEl.textContent = 'Enviando ' + arquivosOtimizados.length + ' foto(s)...';
        progBar.style.width = '8%';

        var base = new FormData(); // sem campos extras

        uploadSequencial(
            'admin.php?ajax=upload_home',
            base,
            arquivosOtimizados,
            function(pct) { progBar.style.width = pct + '%'; },
            function(paths, atual, total) {
                statusEl.textContent = 'Enviado ' + atual + ' de ' + total + '...';
                if (grid) {
                    var empty = grid.querySelector('p');
                    if (empty) empty.remove();
                    paths.forEach(function(p) {
                        var card = document.createElement('div');
                        card.className = 'home-photo-card';
                        card.setAttribute('data-foto', p);
                        card.innerHTML = '<img src="' + p + '?v=' + Date.now() + '" alt="" onerror="this.src=\'fotos_predio/foto_predio_1.jpg\'">'
                            + '<button type="button" class="btn-remove-home" onclick="removerFotoHome(\'' + p.replace(/'/g, "\\'") + '\', this)">✕ Remover</button>';
                        grid.appendChild(card);
                    });
                }
            },
            function(enviados, erros) {
                progBar.style.width = '100%';
                liberarWakeLock();
                var msg = enviados.length > 0
                    ? '✅ ' + enviados.length + ' foto(s) adicionada(s)!'
                    : '❌ Nenhuma foto foi adicionada.';
                if (erros.length > 0) msg += ' ⚠️ ' + erros.length + ' erro(s).';
                statusEl.className = enviados.length > 0 ? 'upload-status ok' : 'upload-status err';
                statusEl.textContent = msg;
                if (enviados.length > 0) showToast(msg, true);
                setTimeout(function(){ progWrap.style.display='none'; progBar.style.width='0%'; }, 3000);
                input.value = '';
            }
        );
    }).catch(function(err) {
        liberarWakeLock();
        statusEl.className = 'upload-status err';
        statusEl.textContent = '❌ Erro ao processar fotos. Tente novamente.';
        console.error(err);
        progWrap.style.display = 'none';
        input.value = '';
    });
}

// ===========================
// FOTO: DEFINIR PRINCIPAL
// ===========================
function setMain(salaId, path, btn) {
    secureFetch('admin.php?ajax=set_main_sala', {sala_id: salaId, foto_path: path})
    .then(function(r) {
        if (r.ok) {
            var grid = document.getElementById('photo-grid-' + salaId);
            grid.querySelectorAll('.photo-card').forEach(function(c) {
                c.classList.remove('main-photo');
                var badge = c.querySelector('.photo-badge');
                if (badge) badge.remove();
            });
            var card = btn.closest('.photo-card');
            card.classList.add('main-photo');
            var b = document.createElement('span');
            b.className = 'photo-badge';
            b.textContent = 'PRINCIPAL';
            card.insertBefore(b, card.firstChild);
            showToast('✅ Foto principal alterada!', true);
        }
    });
}

// ===========================
// FOTO: REMOVER DA SALA
// ===========================
function removerFoto(salaId, path, btn) {
    if (!confirm('Remover esta foto?')) return;
    secureFetch('admin.php?ajax=remove_foto_sala', {sala_id: salaId, foto_path: path})
    .then(function(r) {
        if (r.ok) {
            btn.closest('.photo-card').remove();
            showToast('✅ Foto removida!', true);
        }
    });
}

// ===========================
// FOTO: REMOVER DA GALERIA HOME
// ===========================
function removerFotoHome(path, btn) {
    if (!confirm('Remover esta foto da galeria?')) return;
    secureFetch('admin.php?ajax=remove_foto_home', {foto_path: path})
    .then(function(r) {
        if (r.ok) {
            btn.closest('.home-photo-card').remove();
            showToast('✅ Foto removida da galeria!', true);
        }
    });
}

// ===========================
// DRAG & DROP
// ===========================
document.querySelectorAll('.upload-zone').forEach(function(zone) {
    zone.addEventListener('dragover', function(e) { e.preventDefault(); zone.classList.add('drag-over'); });
    zone.addEventListener('dragleave', function() { zone.classList.remove('drag-over'); });
    zone.addEventListener('drop', function(e) {
        e.preventDefault();
        zone.classList.remove('drag-over');
        var input = zone.querySelector('input[type=file]');
        if (input && e.dataTransfer.files.length > 0) {
            // DataTransfer não pode ser atribuído diretamente, usamos um evento
            var dt = e.dataTransfer;
            // Chamar o handler correto
            if (zone.id === 'uz-home') {
                var fakeInput = { files: dt.files };
                uploadFotosHome(fakeInput);
            } else {
                var salaId = parseInt(zone.id.replace('uz-',''));
                if (salaId) uploadFotosSala(salaId, { files: dt.files, value: '' });
            }
        }
    });
});

// ===========================
// DINÂMICOS
// ===========================
function addSpec(id) {
    var c = document.getElementById('specs_'+id);
    var d = document.createElement('div');
    d.className='dynamic-row spec-row';
    d.innerHTML='<input type="text" name="spec_icon[]" value="📋" style="text-align:center" maxlength="3">'
        +'<input type="text" name="spec_titulo[]" placeholder="Título">'
        +'<input type="text" name="spec_valor[]" placeholder="Valor">'
        +'<button type="button" class="btn-remove" onclick="this.parentElement.remove()">✕</button>';
    c.appendChild(d);
}
function addCar(id) {
    var c = document.getElementById('cars_'+id);
    var d = document.createElement('div');
    d.className='dynamic-row car-row';
    d.innerHTML='<input type="text" name="caracteristicas[]" placeholder="Característica">'
        +'<button type="button" class="btn-remove" onclick="this.parentElement.remove()">✕</button>';
    c.appendChild(d);
}
function addFac(id) {
    var c = document.getElementById('facs_'+id);
    var d = document.createElement('div');
    d.className='dynamic-row fac-row';
    d.innerHTML='<input type="text" name="fac_icon[]" value="🏢" style="text-align:center" maxlength="3">'
        +'<input type="text" name="fac_valor[]" placeholder="Facilidade">'
        +'<button type="button" class="btn-remove" onclick="this.parentElement.remove()">✕</button>';
    c.appendChild(d);
}

// Modal
var modalAdd = document.getElementById('modal-add');
if (modalAdd) {
    modalAdd.addEventListener('click', function(e){ if(e.target===this) this.classList.remove('active'); });
}

/* ═══════ HELPER: upload sequencial com barra de progresso ═══════ */
function uploadSequencialFotos(arquivos, ajaxAction, extraData, progBar, progWrap, statEl, contFotos) {
    if (!arquivos || !arquivos.length) return;

    progWrap.style.display = 'block';
    progBar.style.width = '5%';
    statEl.textContent = 'Otimizando ' + arquivos.length + ' foto(s)...';
    statEl.className = 'mini-status';

    // ── Comprime ANTES de enviar (mesmo mecanismo das Fotos do Prédio) ──
    var qtdImg = arquivos.filter(function(f){ return f.type && f.type.startsWith('image/') && f.type !== 'image/gif'; }).length;
    var compressPromises = arquivos.map(comprimirArquivo);

    Promise.all(compressPromises).then(function(comprimidos) {
        var origMB  = arquivos.reduce(function(s,f){ return s + f.size; }, 0) / 1048576;
        var novoMB  = comprimidos.reduce(function(s,f){ return s + f.size; }, 0) / 1048576;
        var total   = comprimidos.length;
        var idx     = 0;

        statEl.textContent = 'Enviando ' + total + ' foto(s) (' + novoMB.toFixed(1) + 'MB)...';
        progBar.style.width = '8%';

        function enviarUm() {
            if (idx >= total) {
                progBar.style.width = '100%';
                var eco = origMB > novoMB + 0.05 ? ' (era ' + origMB.toFixed(1) + 'MB)' : '';
                statEl.textContent = '✅ ' + total + ' foto(s) salva(s)! ' + novoMB.toFixed(1) + 'MB' + eco;
                statEl.className = 'mini-status ok';
                setTimeout(function(){ progWrap.style.display='none'; progBar.style.width='0%'; }, 3500);
                return;
            }
            var arquivo = comprimidos[idx];
            var fd = new FormData();
            for (var k in extraData) fd.append(k, extraData[k]);
            fd.append('csrf_token', CSRF_TOKEN);
            fd.append('fotos[]', arquivo);

            var xhr = new XMLHttpRequest();
            xhr.open('POST', 'admin.php?ajax=' + ajaxAction);
            xhr.upload.onprogress = function(e) {
                if (e.lengthComputable) {
                    var pct = Math.round(((idx + e.loaded / e.total) / total) * 90) + 8;
                    progBar.style.width = Math.min(pct, 98) + '%';
                }
            };
            xhr.onload = function() {
                idx++;
                try {
                    var r = JSON.parse(xhr.responseText);
                    statEl.textContent = idx + '/' + total + ' enviada(s)...';
                    if (r.ok && r.paths && contFotos) {
                        r.paths.forEach(function(p) { adicionarFotoThumb(contFotos, p); });
                    } else if (!r.ok) {
                        statEl.textContent = '⚠️ Erro: ' + (r.msg || 'falha ao salvar');
                        statEl.className = 'mini-status err';
                    }
                } catch(e) {
                    console.warn('parse error', xhr.responseText && xhr.responseText.substring(0, 200));
                }
                enviarUm();
            };
            xhr.onerror = function() {
                statEl.textContent = '❌ Falha de rede';
                statEl.className = 'mini-status err';
                idx++;
                enviarUm();
            };
            xhr.send(fd);
        }
        enviarUm();
    }).catch(function(err) {
        statEl.textContent = '❌ Erro ao processar fotos: ' + err;
        statEl.className = 'mini-status err';
        progWrap.style.display = 'none';
    });
}
function adicionarFotoThumb(cont, caminho) {
    var ph = cont.querySelector('.sem-fotos');
    if (ph) ph.remove();
    var div = document.createElement('div');
    div.className = 'foto-thumb';
    div.innerHTML = '<img src="' + caminho + '?t=' + Date.now() + '" alt="">'
        + '<button type="button" onclick="this.parentElement.remove()">✕</button>';
    cont.appendChild(div);
}

/* ═══════ PONTOS ESTRATÉGICOS ═══════ */
function editarNomePonto(id, nome) {
    var n = prompt('Novo nome:', nome);
    if (!n || !n.trim()) return;
    var fd = new FormData();
    fd.append('id', id); fd.append('nome', n.trim()); fd.append('csrf_token', CSRF_TOKEN);
    fetch('admin.php?ajax=save_ponto', {method:'POST',body:fd})
        .then(function(r){return r.json();})
        .then(function(r){if(r.ok)location.reload();else alert(r.msg);});
}

/* ═══════ CLIENTES — Editar nome ═══════ */
function editarNomeCliente(id, nome) {
    var n = prompt('Novo nome do cliente:', nome);
    if (n === null) return; // cancelou
    n = n.trim();
    if (!n) { alert('O nome não pode ficar vazio.'); return; }
    var fd = new FormData();
    fd.append('id', id); fd.append('nome', n); fd.append('csrf_token', CSRF_TOKEN);
    fetch('admin.php?ajax=save_cliente', {method:'POST',body:fd})
        .then(function(r){return r.json();})
        .then(function(r){
            if (r.ok) {
                // Atualiza o nome na tela sem precisar recarregar a página
                var card = document.getElementById('cli-card-' + id);
                if (card) {
                    var span = card.querySelector('.item-admin-header span[style*="font-weight:700"]');
                    if (span) span.textContent = n;
                }
                showToast('✅ Nome atualizado para: ' + n, true);
            } else {
                alert(r.msg || 'Erro ao salvar.');
            }
        })
        .catch(function(){ alert('Erro de rede.'); });
}
function uploadFotosPonto(id, nome, input) {
    var files = Array.from(input.files);
    if (!files.length) return;
    uploadSequencialFotos(files, 'upload_foto_ponto', {id:id,nome:nome},
        document.getElementById('prog-pt-'+id),
        document.getElementById('prog-wrap-pt-'+id),
        document.getElementById('status-pt-'+id),
        document.getElementById('fotos-pt-'+id));
    input.value = '';
}
function removerFotoPonto(id, foto, btn) {
    if (!confirm('Remover esta foto?')) return;
    secureFetch('admin.php?ajax=delete_foto_ponto', {id:id,foto:foto})
        .then(function(r){if(r.ok) btn.closest('.foto-thumb').remove();});
}
function mostrarFormNovoPonto() {
    document.getElementById('form-novo-ponto').style.display='block';
    document.getElementById('np-nome').focus();
}
function salvarNovoPonto() {
    var nome=document.getElementById('np-nome').value.trim();
    var stat=document.getElementById('np-status');
    if(!nome){stat.textContent='⚠️ Digite o nome';return;}
    stat.textContent='Criando...';
    var fd=new FormData(); fd.append('id',0); fd.append('nome',nome); fd.append('csrf_token',CSRF_TOKEN);
    fetch('admin.php?ajax=save_ponto',{method:'POST',body:fd})
        .then(function(r){return r.json();})
        .then(function(r){stat.textContent=r.msg;if(r.ok)setTimeout(function(){location.reload();},600);})
        .catch(function(){stat.textContent='❌ Erro de rede';});
}
function deletarPonto(id) {
    if(!confirm('Remover este ponto?')) return;
    secureFetch('admin.php?ajax=delete_ponto', {id:id})
        .then(function(r){if(r.ok) document.getElementById('pr-'+id).remove();});
}

/* ═══════ CLIENTES ═══════ */
function uploadFotosCli(id, nome, input) {
    var files = Array.from(input.files);
    if (!files.length) return;
    uploadSequencialFotos(files, 'upload_foto_cliente', {id:id,nome:nome},
        document.getElementById('prog-cli-'+id),
        document.getElementById('prog-wrap-cli-'+id),
        document.getElementById('status-cli-'+id),
        document.getElementById('fotos-cli-'+id));
    input.value = '';
}
function removerFotoCli(id, foto, btn) {
    if (!confirm('Remover esta foto?')) return;
    secureFetch('admin.php?ajax=delete_foto_cliente', {id:id,foto:foto})
        .then(function(r){if(r.ok) btn.closest('.foto-thumb').remove();});
}
function mostrarFormNovoCliente() {
    document.getElementById('form-novo-cli').style.display='block';
    document.getElementById('nc-nome').focus();
}
function salvarNovoCliente() {
    var nome=document.getElementById('nc-nome').value.trim();
    var stat=document.getElementById('nc-status');
    if(!nome){stat.textContent='⚠️ Digite o nome';return;}
    stat.textContent='Criando...';
    var fd=new FormData(); fd.append('id',0); fd.append('nome',nome); fd.append('ativo','1'); fd.append('csrf_token',CSRF_TOKEN);
    fetch('admin.php?ajax=save_cliente',{method:'POST',body:fd})
        .then(function(r){return r.json();})
        .then(function(r){stat.textContent=r.msg;if(r.ok)setTimeout(function(){location.reload();},600);})
        .catch(function(){stat.textContent='❌ Erro de rede';});
}
function deletarCliente(id) {
    if(!confirm('Remover este cliente?')) return;
    secureFetch('admin.php?ajax=delete_cliente', {id:id})
        .then(function(r){if(r.ok) location.reload();});
}
function toggleCliente(id) {
    secureFetch('admin.php?ajax=toggle_cliente', {id:id})
        .then(function(r){if(r.ok) location.reload();});
}

/* ═══════ VÍDEO HOME — YouTube URL ═══════ */
function salvarYoutubeUrl() {
    var url = document.getElementById('youtube-url-input').value.trim();
    var stat = document.getElementById('youtube-url-status');
    if (!url) { stat.textContent = '⚠️ Cole a URL do YouTube'; stat.style.color='#c62828'; return; }
    stat.textContent = 'Salvando...'; stat.style.color='#555';
    secureFetch('admin.php?ajax=save_youtube_url', {youtube_url: url})
        .then(function(r) {
            stat.textContent = r.msg || (r.ok ? '✅ Salvo!' : '❌ Erro');
            stat.style.color = r.ok ? '#1a8a4a' : '#c62828';
            if (r.ok) setTimeout(function(){ location.reload(); }, 800);
        })
        .catch(function(){ stat.textContent='❌ Erro de rede'; stat.style.color='#c62828'; });
}
function removerYoutubeUrl() {
    if (!confirm('Remover o vídeo YouTube da home?')) return;
    secureFetch('admin.php?ajax=save_youtube_url', {youtube_url: ''})
        .then(function(r) { if (r.ok) location.reload(); });
}
</script>
</body>
</html>
