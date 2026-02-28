<?php
/**
 * Zibll OAuth PHP 示例
 *
 * 本示例演示如何使用 PHP 调用 Zibll OAuth2 接口
 */

// 配置信息（请替换为实际值）
$config = array(
    'base_url'     => 'https://www.example.com/wp-json/zibll-oauth/v1',
    'app_id'       => 'zo_xxxxxxxx',
    'app_key'      => 'your_appkey_here',
    'redirect_uri' => 'https://your-app.example.com/oauth/callback',
);

/**
 * 发送 HTTP 请求
 *
 * @param string $url    请求 URL
 * @param string $method 请求方法
 * @param array  $data   请求数据
 * @param array  $headers 请求头
 * @return array
 */
function http_request($url, $method = 'GET', $data = array(), $headers = array())
{
    $ch = curl_init();

    $default_headers = array(
        'Accept: application/json',
    );
    $headers = array_merge($default_headers, $headers);

    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

    if ($method === 'POST') {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
    }

    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);

    if ($error) {
        return array('error' => $error, 'http_code' => $http_code);
    }

    $decoded = json_decode($response, true);
    return array(
        'data'      => $decoded,
        'http_code' => $http_code,
        'raw'       => $response,
    );
}

/**
 * 1. 发起授权（获取授权 URL）
 *
 * @param array  $config 配置信息
 * @param string $state  随机状态值（用于防 CSRF）
 * @param string $scope  授权范围
 * @return string 授权 URL
 */
function build_authorize_url($config, $state, $scope = 'basic email profile')
{
    $params = array(
        'response_type' => 'code',
        'client_id'     => $config['app_id'],
        'redirect_uri'  => $config['redirect_uri'],
        'state'         => $state,
        'scope'         => $scope,
    );

    return $config['base_url'] . '/authorize?' . http_build_query($params);
}

/**
 * 2. 发起财务授权（获取财务授权 URL）
 *
 * @param array  $config 配置信息
 * @param string $state  随机状态值
 * @return string 财务授权 URL
 */
function build_authorize_finance_url($config, $state)
{
    $params = array(
        'response_type' => 'code',
        'client_id'     => $config['app_id'],
        'redirect_uri'  => $config['redirect_uri'],
        'state'         => $state,
    );

    return $config['base_url'] . '/authorize_finance?' . http_build_query($params);
}

/**
 * 3. 使用 code 换取 token
 *
 * @param array  $config 配置信息
 * @param string $code   授权码
 * @return array|null
 */
function get_token_by_code($config, $code)
{
    $url = $config['base_url'] . '/token';

    $data = array(
        'grant_type'    => 'authorization_code',
        'client_id'     => $config['app_id'],
        'client_secret' => $config['app_key'],
        'code'          => $code,
        'redirect_uri'  => $config['redirect_uri'],
    );

    $result = http_request($url, 'POST', $data);

    if ($result['http_code'] === 200 && isset($result['data']['access_token'])) {
        return $result['data'];
    }

    return null;
}

/**
 * 4. 获取用户信息
 *
 * @param array  $config      配置信息
 * @param string $access_token 访问令牌
 * @return array|null
 */
function get_user_info($config, $access_token)
{
    $url = $config['base_url'] . '/userinfo';

    $headers = array(
        'Authorization: Bearer ' . $access_token,
    );

    $result = http_request($url, 'GET', array(), $headers);

    if ($result['http_code'] === 200 && isset($result['data']['userinfo'])) {
        return $result['data']['userinfo'];
    }

    return null;
}

/**
 * 5. 判断用户是否有财务权限
 *
 * 通过检查 userinfo 中是否包含 balance 字段来判断
 *
 * @param array  $config      配置信息
 * @param string $access_token 访问令牌
 * @return bool
 */
function has_finance_permission($config, $access_token)
{
    $userinfo = get_user_info($config, $access_token);

    if ($userinfo && array_key_exists('balance', $userinfo)) {
        return true;
    }

    return false;
}

/**
 * 6. 获取用户签约状态（新接口）
 *
 * @param array  $config      配置信息
 * @param string $access_token 访问令牌
 * @return array|null
 */
function get_finance_sign_status($config, $access_token)
{
    $url = $config['base_url'] . '/finance/sign_status';

    $headers = array(
        'Authorization: Bearer ' . $access_token,
    );

    $result = http_request($url, 'GET', array(), $headers);

    if ($result['http_code'] === 200) {
        return $result['data'];
    }

    return null;
}

/**
 * 7. 发起扣款
 *
 * @param array  $config      配置信息
 * @param string $access_token 访问令牌
 * @param string $product_name 商品名称
 * @param float  $amount      金额
 * @param string $order_no    订单号
 * @return array|null
 */
function finance_deduct($config, $access_token, $product_name, $amount, $order_no)
{
    $url = $config['base_url'] . '/finance/deduct';

    $data = array(
        'product_name' => $product_name,
        'amount'       => $amount,
        'order_no'     => $order_no,
    );

    $headers = array(
        'Authorization: Bearer ' . $access_token,
        'Content-Type: application/x-www-form-urlencoded',
    );

    $result = http_request($url, 'POST', $data, $headers);

    if (in_array($result['http_code'], array(200, 202))) {
        return $result['data'];
    }

    return null;
}

/**
 * 8. 查询扣款结果
 *
 * @param array  $config      配置信息
 * @param string $access_token 访问令牌
 * @param string $trade_no    交易号
 * @param string $order_no    订单号
 * @return array|null
 */
function finance_verify($config, $access_token, $trade_no = '', $order_no = '')
{
    $url = $config['base_url'] . '/finance/verify';

    $params = array();
    if ($trade_no) {
        $params['trade_no'] = $trade_no;
    } elseif ($order_no) {
        $params['order_no'] = $order_no;
    }

    if (!empty($params)) {
        $url .= '?' . http_build_query($params);
    }

    $headers = array(
        'Authorization: Bearer ' . $access_token,
    );

    $result = http_request($url, 'GET', array(), $headers);

    if ($result['http_code'] === 200) {
        return $result['data'];
    }

    return null;
}

// ============ 使用示例 ============

// 示例 1: 构建授权 URL
// $state = bin2hex(random_bytes(16));
// $authorize_url = build_authorize_url($config, $state);
// header('Location: ' . $authorize_url);

// 示例 2: 回调处理 - 用 code 换 token
// $code = $_GET['code'] ?? '';
// if ($code) {
//     $token = get_token_by_code($config, $code);
//     if ($token) {
//         $access_token = $token['access_token'];
//         $refresh_token = $token['refresh_token'];
//         // 保存 token 到 session 或数据库
//     }
// }

// 示例 3: 获取用户签约状态
// $sign_status = get_finance_sign_status($config, $access_token);
// if ($sign_status) {
//     echo "用户 OpenID: " . $sign_status['openid'] . "\n";
//     echo "是否已签约: " . ($sign_status['is_signed'] ? '是' : '否') . "\n";
//     echo "财务授权状态: " . $sign_status['finance_scope'] . "\n";
//     echo "授权时间: " . ($sign_status['authorized_at'] ?? '未授权') . "\n";
// }

// 示例 4: 发起扣款
// $order_no = 'ORD_' . date('YmdHis') . rand(1000, 9999);
// $deduct_result = finance_deduct($config, $access_token, '示例商品', 10.00, $order_no);
// if ($deduct_result) {
//     echo "交易号: " . $deduct_result['trade_no'] . "\n";
//     echo "状态: " . $deduct_result['status'] . "\n";
// }

// 示例 5: 查询扣款结果
// $verify_result = finance_verify($config, $access_token, $deduct_result['trade_no']);
// if ($verify_result) {
//     echo "扣款状态: " . $verify_result['status'] . "\n";
//     echo "金额: " . $verify_result['amount'] . "\n";
// }
