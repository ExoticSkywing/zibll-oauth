<?php
/**
 * OpenID Connect (OIDC 1.0) 核心模块
 *
 * 负责提供标准 OIDC 自动发现（Discovery）、RS256 非对称密钥加载与 JWKS 公钥集导出、
 * id_token (JWT) 签发与校验，遵循零硬编码密钥、拒绝 alg=none 及最小权限原则。
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Zibll_Oauth_OIDC
{
    const ALG = 'RS256';
    const DEFAULT_ID_TOKEN_TTL = 3600;

    /** @var array|null 仅限测试或单请求注入的内存密钥集合 */
    private static $keys_override = null;

    /**
     * 设置测试用密钥覆盖（传 null 清除）
     *
     * @param array|null $keys
     * @return void
     */
    public static function set_keys_override($keys)
    {
        self::$keys_override = is_array($keys) ? $keys : null;
    }

    /**
     * 获取标准 OIDC Issuer URL（不含末尾斜杠）
     *
     * @return string
     */
    public static function issuer()
    {
        if (defined('ZIBLL_OAUTH_OIDC_ISSUER') && is_string(ZIBLL_OAUTH_OIDC_ISSUER) && ZIBLL_OAUTH_OIDC_ISSUER !== '') {
            return rtrim(ZIBLL_OAUTH_OIDC_ISSUER, '/');
        }
        return rtrim((string) rest_url(Zibll_Oauth_Rest::REST_NAMESPACE), '/');
    }

    /**
     * 解析站外 OIDC 私钥文件路径
     *
     * @return string
     */
    public static function default_keys_file_path()
    {
        if (defined('ZIBLL_OAUTH_OIDC_KEYS_FILE') && is_string(ZIBLL_OAUTH_OIDC_KEYS_FILE) && ZIBLL_OAUTH_OIDC_KEYS_FILE !== '') {
            return ZIBLL_OAUTH_OIDC_KEYS_FILE;
        }
        if (!defined('ABSPATH')) {
            return '';
        }
        $root = rtrim((string) ABSPATH, '/\\');
        return dirname($root) . '/.xingxy-private/' . basename($root) . '/oauth-oidc-keys.php';
    }

    /**
     * 生成新的 2048 位 RSA 签名密钥条目
     *
     * @return array|WP_Error
     */
    public static function generate_rsa_key_entry()
    {
        if (!function_exists('openssl_pkey_new')) {
            return new WP_Error('oidc_crypto_unavailable', '服务器未启用 OpenSSL 扩展，无法生成 OIDC 密钥', array('status' => 500));
        }

        $res = @openssl_pkey_new(array(
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ));
        if (!$res) {
            return new WP_Error('oidc_keygen_failed', '生成 RSA 密钥对失败', array('status' => 500));
        }

        $private_pem = '';
        if (!@openssl_pkey_export($res, $private_pem) || !is_string($private_pem) || $private_pem === '') {
            return new WP_Error('oidc_keygen_failed', '导出 RSA 私钥失败', array('status' => 500));
        }

        $details = @openssl_pkey_get_details($res);
        if (!is_array($details) || empty($details['key']) || empty($details['rsa']['n']) || empty($details['rsa']['e'])) {
            return new WP_Error('oidc_keygen_failed', '解析 RSA 公钥细节失败', array('status' => 500));
        }

        // kid 由公钥 SHA-256 摘要前 16 位十六进制构成，与私钥脱敏
        $kid = 'k_' . substr(hash('sha256', $details['key']), 0, 16);

        return array(
            'kid'         => $kid,
            'alg'         => self::ALG,
            'private_pem' => $private_pem,
            'public_pem'  => (string) $details['key'],
            'created_at'  => time(),
        );
    }

    /**
     * 在受保护的站外私有文件路径原子初始化 OIDC RSA 密钥（供 CLI/安装部署调用）
     *
     * @param string $path 目标文件路径，留空使用默认私有目录路径
     * @return array|WP_Error
     */
    public static function provision_keys_file($path = '')
    {
        $target = $path !== '' ? (string) $path : self::default_keys_file_path();
        if ($target === '') {
            return new WP_Error('oidc_keys_path_invalid', '未指定有效的 OIDC 密钥文件路径', array('status' => 500));
        }

        if (is_file($target) && is_readable($target)) {
            $loaded = self::load_keys_from_file($target);
            if (!is_wp_error($loaded)) {
                return $loaded;
            }
        }

        $dir = dirname($target);
        if (!is_dir($dir)) {
            if (!@mkdir($dir, 0750, true) && !is_dir($dir)) {
                return new WP_Error('oidc_keys_dir_unwritable', '无法创建私有密钥目录', array('status' => 500));
            }
        }

        $entry = self::generate_rsa_key_entry();
        if (is_wp_error($entry)) {
            return $entry;
        }

        $payload = array(
            'active_kid' => $entry['kid'],
            'keys'       => array(
                $entry['kid'] => $entry,
            ),
        );

        $export = var_export($payload, true);
        $php = "<?php\nif (!defined('ABSPATH')) {\n    exit;\n}\nreturn " . $export . ";\n";

        $tmp = $target . '.tmp.' . getmypid();
        if (@file_put_contents($tmp, $php, LOCK_EX) === false) {
            @unlink($tmp);
            return new WP_Error('oidc_keys_write_failed', '写入 OIDC 密钥文件失败', array('status' => 500));
        }
        @chmod($tmp, 0640);
        if (!@rename($tmp, $target)) {
            @unlink($tmp);
            return new WP_Error('oidc_keys_write_failed', '替换 OIDC 密钥文件失败', array('status' => 500));
        }
        @chmod($target, 0640);

        return $payload;
    }

    /**
     * 安全加载所有可用签名与验签密钥（常量/环境变量 -> 站外受保护私有文件）
     *
     * @return array|WP_Error
     */
    private static function load_keyset()
    {
        if (is_array(self::$keys_override) && !empty(self::$keys_override['keys'])) {
            return self::$keys_override;
        }

        // 1. 支持通过常量或环境变量注入私钥 PEM
        $env_pem = '';
        if (defined('ZIBLL_OAUTH_OIDC_PRIVATE_KEY') && is_string(ZIBLL_OAUTH_OIDC_PRIVATE_KEY)) {
            $env_pem = ZIBLL_OAUTH_OIDC_PRIVATE_KEY;
        } elseif (getenv('ZIBLL_OAUTH_OIDC_PRIVATE_KEY')) {
            $env_pem = (string) getenv('ZIBLL_OAUTH_OIDC_PRIVATE_KEY');
        }

        if (trim($env_pem) !== '' && function_exists('openssl_pkey_get_private')) {
            $res = @openssl_pkey_get_private($env_pem);
            if ($res) {
                $details = @openssl_pkey_get_details($res);
                if (is_array($details) && !empty($details['key'])) {
                    $kid = defined('ZIBLL_OAUTH_OIDC_KID') && is_string(ZIBLL_OAUTH_OIDC_KID) && ZIBLL_OAUTH_OIDC_KID !== ''
                        ? ZIBLL_OAUTH_OIDC_KID
                        : 'k_' . substr(hash('sha256', $details['key']), 0, 16);
                    return array(
                        'active_kid' => $kid,
                        'keys'       => array(
                            $kid => array(
                                'kid'         => $kid,
                                'alg'         => self::ALG,
                                'private_pem' => $env_pem,
                                'public_pem'  => (string) $details['key'],
                            ),
                        ),
                    );
                }
            }
        }

        // 2. 加载站外私有密钥文件
        $path = self::default_keys_file_path();
        if ($path !== '' && is_file($path) && is_readable($path)) {
            $loaded = self::load_keys_from_file($path);
            if (!is_wp_error($loaded)) {
                return $loaded;
            }
            return $loaded;
        }

        // 3. 若私密文件尚未初始化且当前进程对目标目录具备写权限，则尝试安全首次初始化
        if ($path !== '' && is_dir(dirname($path)) && is_writable(dirname($path))) {
            return self::provision_keys_file($path);
        }

        // 严格 Fail-Closed：绝不使用硬编码默认密钥
        return new WP_Error('oidc_keys_unconfigured', 'OIDC 签名密钥尚未在安全位置配置', array('status' => 500));
    }

    /**
     * 从受保护的 PHP 配置文件载入密钥数组
     *
     * @param string $path
     * @return array|WP_Error
     */
    private static function load_keys_from_file($path)
    {
        $data = require $path;
        if (!is_array($data) || empty($data['keys']) || !is_array($data['keys'])) {
            return new WP_Error('oidc_keys_invalid', 'OIDC 密钥文件格式无效', array('status' => 500));
        }

        $active_kid = !empty($data['active_kid']) ? (string) $data['active_kid'] : '';
        if ($active_kid === '' || empty($data['keys'][$active_kid])) {
            $keys_list = array_keys($data['keys']);
            $active_kid = (string) reset($keys_list);
        }

        return array(
            'active_kid' => $active_kid,
            'keys'       => $data['keys'],
        );
    }

    /**
     * 校验 nonce 参数格式是否安全合法
     *
     * @param mixed $nonce
     * @return bool
     */
    public static function is_valid_nonce($nonce)
    {
        if ($nonce === null || $nonce === '') {
            return true;
        }
        if (!is_string($nonce) || strlen($nonce) > 255) {
            return false;
        }
        return preg_match('/\A[\x21-\x7e]{1,255}\z/', $nonce) === 1;
    }

    /**
     * 判断请求 scope 是否包含 openid
     *
     * @param string $scope
     * @return bool
     */
    public static function has_openid_scope($scope)
    {
        $parts = preg_split('/[\s,]+/', trim((string) $scope));
        return is_array($parts) && in_array('openid', $parts, true);
    }

    /**
     * 导出标准 JWKS 公钥集合
     *
     * @return array|WP_Error
     */
    public static function public_jwks()
    {
        $keyset = self::load_keyset();
        if (is_wp_error($keyset)) {
            return $keyset;
        }

        $jwks = array();
        foreach ($keyset['keys'] as $kid => $entry) {
            if (!is_array($entry)) {
                continue;
            }
            $pub_pem = !empty($entry['public_pem']) ? (string) $entry['public_pem'] : '';
            if ($pub_pem === '' && !empty($entry['private_pem']) && function_exists('openssl_pkey_get_private')) {
                $priv = @openssl_pkey_get_private((string) $entry['private_pem']);
                if ($priv) {
                    $d = @openssl_pkey_get_details($priv);
                    if (is_array($d) && !empty($d['key'])) {
                        $pub_pem = (string) $d['key'];
                    }
                }
            }
            if ($pub_pem === '' || !function_exists('openssl_pkey_get_public')) {
                continue;
            }

            $pub_res = @openssl_pkey_get_public($pub_pem);
            if (!$pub_res) {
                continue;
            }
            $details = @openssl_pkey_get_details($pub_res);
            if (!is_array($details) || empty($details['rsa']['n']) || empty($details['rsa']['e'])) {
                continue;
            }

            // 去除 n 前导零字节符合 JWK RFC 7518 要求
            $n_bin = ltrim((string) $details['rsa']['n'], "\x00");
            $e_bin = ltrim((string) $details['rsa']['e'], "\x00");

            $jwks[] = array(
                'kty' => 'RSA',
                'use' => 'sig',
                'alg' => self::ALG,
                'kid' => !empty($entry['kid']) ? (string) $entry['kid'] : (string) $kid,
                'n'   => self::base64url_encode($n_bin),
                'e'   => self::base64url_encode($e_bin),
            );
        }

        if (empty($jwks)) {
            return new WP_Error('oidc_jwks_empty', '当前无可用 OIDC 公钥', array('status' => 500));
        }

        return array('keys' => $jwks);
    }

    /**
     * 计算 OIDC Core 规定的 at_hash（RS256 对应 SHA-256 左半 128 位）
     *
     * @param string $access_token
     * @return string
     */
    public static function compute_at_hash($access_token)
    {
        $digest = hash('sha256', (string) $access_token, true);
        return self::base64url_encode(substr($digest, 0, 16));
    }

    /**
     * 构造标准 OIDC id_token Payload Claims 并签名为 RS256 JWT
     *
     * @param string $appid
     * @param int    $user_id
     * @param string $scope
     * @param string $access_token
     * @param string $nonce
     * @param int    $auth_time
     * @param int    $ttl
     * @return string|WP_Error
     */
    public static function issue_id_token($appid, $user_id, $scope, $access_token, $nonce = '', $auth_time = 0, $ttl = 0)
    {
        $openid = Zibll_Oauth_Provider_Util::get_openid((int) $user_id, (string) $appid);
        if ($openid === '') {
            return new WP_Error('openid_error', 'OpenID 生成失败', array('status' => 500));
        }

        $userinfo = Zibll_Oauth_Provider_Util::wp_userinfo_by_scope((int) $user_id, (string) $scope, (string) $appid, false);
        if (is_wp_error($userinfo)) {
            return $userinfo;
        }

        $now = time();
        $ttl = (int) $ttl;
        if ($ttl <= 0) {
            $ttl = class_exists('Zibll_Oauth_Options') ? min(self::DEFAULT_ID_TOKEN_TTL, Zibll_Oauth_Options::token_expires()) : self::DEFAULT_ID_TOKEN_TTL;
        }
        $ttl = max(60, $ttl);
        $auth_time = $auth_time > 0 ? (int) $auth_time : $now;

        $claims = array(
            'iss'       => self::issuer(),
            'sub'       => $openid,
            'aud'       => (string) $appid,
            'exp'       => $now + $ttl,
            'iat'       => $now,
            'auth_time' => $auth_time,
            'uid'       => (int) $user_id,
            'name'      => (string) ($userinfo['name'] ?? ''),
            'picture'   => (string) ($userinfo['picture'] ?? ''),
        );

        if ($access_token !== '') {
            $claims['at_hash'] = self::compute_at_hash($access_token);
        }

        if ($nonce !== '' && self::is_valid_nonce($nonce)) {
            $claims['nonce'] = (string) $nonce;
        }

        if (isset($userinfo['email'])) {
            $claims['email'] = (string) $userinfo['email'];
            $claims['email_verified'] = !empty($userinfo['email_verified']);
        }

        if (isset($userinfo['tg_uid'])) {
            $claims['tg_uid'] = (int) $userinfo['tg_uid'];
        }

        if (isset($userinfo['segments']) && is_array($userinfo['segments'])) {
            $claims['segments'] = array_values($userinfo['segments']);
        }

        return self::sign_jwt_rs256($claims);
    }

    /**
     * 使用当前激活私钥签发 RS256 JWT
     *
     * @param array $claims
     * @return string|WP_Error
     */
    public static function sign_jwt_rs256($claims)
    {
        if (!function_exists('openssl_sign') || !function_exists('openssl_pkey_get_private')) {
            return new WP_Error('oidc_crypto_unavailable', 'OpenSSL 不可用', array('status' => 500));
        }

        $keyset = self::load_keyset();
        if (is_wp_error($keyset)) {
            return $keyset;
        }

        $kid = (string) $keyset['active_kid'];
        $entry = $keyset['keys'][$kid] ?? null;
        if (!is_array($entry) || empty($entry['private_pem'])) {
            return new WP_Error('oidc_keys_invalid', '未找到可用的签名私钥', array('status' => 500));
        }

        $private_res = @openssl_pkey_get_private((string) $entry['private_pem']);
        if (!$private_res) {
            return new WP_Error('oidc_keys_invalid', '解析签名私钥失败', array('status' => 500));
        }

        $header = array(
            'alg' => self::ALG,
            'typ' => 'JWT',
            'kid' => $kid,
        );

        $header_json = wp_json_encode($header, JSON_UNESCAPED_SLASHES);
        $claims_json = wp_json_encode($claims, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if (!is_string($header_json) || !is_string($claims_json)) {
            return new WP_Error('oidc_encode_failed', 'JWT 序列化失败', array('status' => 500));
        }

        $signing_input = self::base64url_encode($header_json) . '.' . self::base64url_encode($claims_json);
        $signature = '';
        if (!@openssl_sign($signing_input, $signature, $private_res, OPENSSL_ALGO_SHA256) || $signature === '') {
            return new WP_Error('oidc_sign_failed', 'JWT RS256 签名失败', array('status' => 500));
        }

        return $signing_input . '.' . self::base64url_encode($signature);
    }

    /**
     * 使用本地公钥集合校验 RS256 JWT（强制拒绝 alg=none 或算法替换）
     *
     * @param string $jwt
     * @param string $expected_aud
     * @param string $expected_iss
     * @return array|WP_Error 返回解码后的 Claims 数组
     */
    public static function verify_jwt_rs256($jwt, $expected_aud = '', $expected_iss = '')
    {
        if (!function_exists('openssl_verify') || !function_exists('openssl_pkey_get_public')) {
            return new WP_Error('oidc_crypto_unavailable', 'OpenSSL 不可用', array('status' => 500));
        }

        $parts = explode('.', (string) $jwt);
        if (count($parts) !== 3) {
            return new WP_Error('invalid_jwt', 'JWT 格式无效', array('status' => 401));
        }

        list($h_b64, $p_b64, $s_b64) = $parts;
        $header_raw = self::base64url_decode($h_b64);
        $payload_raw = self::base64url_decode($p_b64);
        $sig_raw = self::base64url_decode($s_b64);
        if ($header_raw === false || $payload_raw === false || $sig_raw === false || $sig_raw === '') {
            return new WP_Error('invalid_jwt', 'JWT 解码失败', array('status' => 401));
        }

        $header = json_decode($header_raw, true);
        $claims = json_decode($payload_raw, true);
        if (!is_array($header) || !is_array($claims)) {
            return new WP_Error('invalid_jwt', 'JWT JSON 解析失败', array('status' => 401));
        }

        // 硬编码强校验算法必须为 RS256，严禁信任 none 或从令牌派生弱算法
        if (!isset($header['alg']) || $header['alg'] !== self::ALG) {
            return new WP_Error('invalid_jwt', '不支持的 JWT 签名算法', array('status' => 401));
        }

        $kid = isset($header['kid']) && is_string($header['kid']) ? $header['kid'] : '';
        $keyset = self::load_keyset();
        if (is_wp_error($keyset)) {
            return $keyset;
        }

        $entry = ($kid !== '' && isset($keyset['keys'][$kid])) ? $keyset['keys'][$kid] : null;
        if (!is_array($entry) || empty($entry['public_pem'])) {
            return new WP_Error('invalid_jwt', '未知的密钥 kid', array('status' => 401));
        }

        $pub_res = @openssl_pkey_get_public((string) $entry['public_pem']);
        if (!$pub_res) {
            return new WP_Error('invalid_jwt', '公钥无效', array('status' => 401));
        }

        $verified = @openssl_verify($h_b64 . '.' . $p_b64, $sig_raw, $pub_res, OPENSSL_ALGO_SHA256);
        if ($verified !== 1) {
            return new WP_Error('invalid_jwt', 'JWT 签名验证未通过', array('status' => 401));
        }

        $now = time();
        if (!isset($claims['exp']) || !is_int($claims['exp']) || $claims['exp'] < ($now - 60)) {
            return new WP_Error('invalid_jwt', 'JWT 已过期', array('status' => 401));
        }

        if ($expected_iss !== '' && (!isset($claims['iss']) || !hash_equals((string) $expected_iss, (string) $claims['iss']))) {
            return new WP_Error('invalid_jwt', 'JWT iss 不匹配', array('status' => 401));
        }

        if ($expected_aud !== '' && (!isset($claims['aud']) || !hash_equals((string) $expected_aud, (string) $claims['aud']))) {
            return new WP_Error('invalid_jwt', 'JWT aud 不匹配', array('status' => 401));
        }

        return $claims;
    }

    /**
     * 构建标准 OIDC Discovery Metadata 文档
     *
     * @return array
     */
    public static function discovery_document()
    {
        $issuer = self::issuer();
        return array(
            'issuer'                                => $issuer,
            'authorization_endpoint'                => $issuer . '/authorize',
            'token_endpoint'                        => $issuer . '/token',
            'userinfo_endpoint'                     => $issuer . '/userinfo',
            'jwks_uri'                              => $issuer . '/jwks',
            'revocation_endpoint'                   => $issuer . '/revoke',
            'introspection_endpoint'                => $issuer . '/introspect',
            'response_types_supported'              => array('code'),
            'grant_types_supported'                 => array('authorization_code', 'refresh_token'),
            'subject_types_supported'               => array('public'),
            'id_token_signing_alg_values_supported' => array(self::ALG),
            'token_endpoint_auth_methods_supported' => array('client_secret_basic', 'client_secret_post'),
            'revocation_endpoint_auth_methods_supported' => array('client_secret_basic', 'client_secret_post'),
            'introspection_endpoint_auth_methods_supported' => array('client_secret_basic', 'client_secret_post'),
            'code_challenge_methods_supported'      => array('S256'),
            'scopes_supported'                      => array('openid', 'basic', 'profile', 'email', 'phone', 'telegram', 'segments'),
            'claims_supported'                      => array(
                'iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'at_hash',
                'uid', 'openid', 'name', 'picture', 'avatar', 'email', 'email_verified',
                'phone', 'description', 'tg_uid', 'segments', 'balance',
            ),
        );
    }

    /**
     * Base64URL 编码（无末尾填充 =）
     *
     * @param string $binary
     * @return string
     */
    public static function base64url_encode($binary)
    {
        return rtrim(strtr(base64_encode((string) $binary), '+/', '-_'), '=');
    }

    /**
     * Base64URL 严格解码
     *
     * @param string $encoded
     * @return string|false
     */
    public static function base64url_decode($encoded)
    {
        $encoded = (string) $encoded;
        $rem = strlen($encoded) % 4;
        if ($rem > 0) {
            $encoded .= str_repeat('=', 4 - $rem);
        }
        return base64_decode(strtr($encoded, '-_', '+/'), true);
    }
}
