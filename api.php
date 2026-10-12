<?php
declare(strict_types=1);

/*
 * PANEL P4NTA - API de canje único.
 * Requisitos: PHP 7.4+ y permisos de escritura en la carpeta privada "data".
 * Antes de publicar: cambia ADMIN_SECRET por una contraseña larga y privada.
 * Coloca tu APK autorizada como panel.apk junto a este archivo.
 */
const ADMIN_SECRET = 'P4NTA11';
const APK_FILE = __DIR__ . '/panel.apk';
const DATA_DIR = __DIR__ . '/data';
const DB_FILE = DATA_DIR . '/keys.json';
const TOKEN_TTL = 900; // token de descarga válido durante 15 minutos

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

function json_out(int $status, array $data): never {
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
function body_json(): array {
    $raw = file_get_contents('php://input');
    $data = json_decode($raw ?: '{}', true);
    return is_array($data) ? $data : [];
}
function ensure_store(): void {
    if (!is_dir(DATA_DIR) && !mkdir(DATA_DIR, 0700, true) && !is_dir(DATA_DIR)) {
        json_out(500, ['ok' => false, 'message' => 'No se pudo preparar el almacenamiento del servidor.']);
    }
    if (!file_exists(DB_FILE)) {
        file_put_contents(DB_FILE, json_encode(['keys' => [], 'tokens' => []], JSON_PRETTY_PRINT), LOCK_EX);
        @chmod(DB_FILE, 0600);
    }
}
function with_db(callable $callback) {
    ensure_store();
    $fp = fopen(DB_FILE, 'c+');
    if (!$fp) json_out(500, ['ok' => false, 'message' => 'No se pudo abrir la base de datos.']);
    flock($fp, LOCK_EX);
    $contents = stream_get_contents($fp);
    $db = json_decode($contents ?: '', true);
    if (!is_array($db)) $db = ['keys' => [], 'tokens' => []];
    $db['keys'] = $db['keys'] ?? [];
    $db['tokens'] = $db['tokens'] ?? [];
    $result = $callback($db);
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($db, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    return $result;
}
function admin_ok(string $pin): bool {
    return ADMIN_SECRET !== 'P4NTA11'
        && hash_equals(ADMIN_SECRET, $pin);
}
function random_code(int $bytes = 12): string {
    return strtoupper(bin2hex(random_bytes($bytes)));
}

$action = $_GET['action'] ?? '';
if ($action === 'download') {
    $token = (string)($_GET['token'] ?? '');
    if ($token === '' || !is_file(APK_FILE)) {
        http_response_code(404);
        exit('Descarga no disponible.');
    }
    $valid = with_db(function (&$db) use ($token) {
        foreach ($db['tokens'] as &$item) {
            if (hash_equals((string)($item['hash'] ?? ''), hash('sha256', $token))
                && empty($item['used']) && (int)($item['expires'] ?? 0) >= time()) {
                $item['used'] = true;
                return true;
            }
        }
        return false;
    });
    if (!$valid) {
        http_response_code(403);
        exit('Este enlace ya se usó o expiró. Si no descargaste el APK, contacta al administrador.');
    }
    header_remove('Content-Type');
    header('Content-Type: application/vnd.android.package-archive');
    header('Content-Disposition: attachment; filename="PANEL-P4NTA.apk"');
    header('Content-Length: ' . filesize(APK_FILE));
    readfile(APK_FILE);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_out(405, ['ok' => false, 'message' => 'Método no permitido.']);
}
$input = body_json();
$pin = (string)($input['pin'] ?? '');

if ($action === 'admin_check') {
    if (!admin_ok($pin)) json_out(401, ['ok' => false, 'message' => 'PIN incorrecto. Configura ADMIN_SECRET en api.php.']);
    json_out(200, ['ok' => true]);
}

if ($action === 'generate') {
    if (!admin_ok($pin)) json_out(401, ['ok' => false, 'message' => 'Acceso admin no válido. Vuelve a entrar.']);
    $device = strtoupper(trim((string)($input['device_id'] ?? '')));
    if ($device === '' || strlen($device) > 120) json_out(400, ['ok' => false, 'message' => 'ID del dispositivo no válido.']);
    $key = 'P4NTA-' . random_code(10);
    with_db(function (&$db) use ($key, $device) {
        $db['keys'][hash('sha256', $key)] = [
            'device_id' => $device,
            'created_at' => time(),
            'redeemed' => false
        ];
        return true;
    });
    json_out(200, ['ok' => true, 'key' => $key]);
}

if ($action === 'redeem') {
    $key = strtoupper(trim((string)($input['key'] ?? '')));
    $device = strtoupper(trim((string)($input['device_id'] ?? '')));
    if ($key === '' || $device === '') json_out(400, ['ok' => false, 'message' => 'Escribe tu KEY y genera tu ID primero.']);
    if (strlen($key) > 100 || strlen($device) > 120) json_out(400, ['ok' => false, 'message' => 'Datos no válidos.']);
    if (!is_file(APK_FILE)) json_out(500, ['ok' => false, 'message' => 'El administrador aún no ha subido panel.apk al servidor.']);

    $token = random_code(32);
    $result = with_db(function (&$db) use ($key, $device, $token) {
        $hash = hash('sha256', $key);
        if (!isset($db['keys'][$hash])) return ['error' => 'KEY incorrecta o inexistente.'];
        $item = &$db['keys'][$hash];
        if (!hash_equals((string)$item['device_id'], $device)) return ['error' => 'Esta KEY fue creada para otro ID.'];
        if (!empty($item['redeemed'])) return ['error' => 'Esta KEY ya fue canjeada. Solo se permite un canje.'];
        $item['redeemed'] = true;
        $item['redeemed_at'] = time();
        $db['tokens'][] = [
            'hash' => hash('sha256', $token),
            'expires' => time() + TOKEN_TTL,
            'used' => false
        ];
        return ['success' => true];
    });
    if (isset($result['error'])) json_out(403, ['ok' => false, 'message' => $result['error']]);
    json_out(200, ['ok' => true, 'download_token' => $token]);
}

json_out(404, ['ok' => false, 'message' => 'Acción no encontrada.']);
?>
