<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Zibll_Oauth_Admin_Audit
{
    const PAGE_SLUG = 'zibll_oauth_app_audit';

    public static function init()
    {
        if (!is_admin()) {
            return;
        }

        add_action('admin_menu', array(__CLASS__, 'add_menu'), 50);
        add_action('admin_notices', array(__CLASS__, 'admin_notice_pending'));
    }

    public static function add_menu()
    {
        add_submenu_page(
            'zibll-oauth',
            'OAuth 应用审核',
            '应用审核',
            'manage_options',
            self::PAGE_SLUG,
            array(__CLASS__, 'render_page')
        );
    }

    public static function render_page()
    {
        require __DIR__ . '/admin-audit-page.php';
    }

    public static function admin_notice_pending()
    {
        if (!empty($_GET['page']) && $_GET['page'] === self::PAGE_SLUG) {
            return;
        }

        if (!class_exists('Zibll_Oauth_App_DB')) {
            return;
        }

        $count = self::pending_count();
        if ($count <= 0) {
            return;
        }

        $url = add_query_arg(array('page' => self::PAGE_SLUG, 'status' => Zibll_Oauth_App_DB::STATUS_PENDING), admin_url('admin.php'));
        echo '<div class="notice notice-info is-dismissible">';
        echo '<h3>OAuth 应用审核待处理</h3>';
        echo '<p>您有' . (int) $count . '个 OAuth 应用申请待处理</p>';
        echo '<p><a class="button" href="' . esc_url($url) . '">立即处理</a></p>';
        echo '</div>';
    }

    private static function pending_count()
    {
        global $wpdb;
        $table = Zibll_Oauth_App_DB::table_name();
        $n = $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$table} WHERE status = %d", Zibll_Oauth_App_DB::STATUS_PENDING));
        return $n ? (int) $n : 0;
    }

    public static function notify_audit_result($app_row, $new_status, $reject_reason = '')
    {
        if (!is_array($app_row)) {
            return;
        }

        $user_id = !empty($app_row['user_id']) ? (int) $app_row['user_id'] : 0;
        if ($user_id <= 0) {
            return;
        }

        $user = get_user_by('id', $user_id);
        if (!$user) {
            return;
        }

        $app_name = !empty($app_row['title']) ? (string) $app_row['title'] : '';
        $appid = !empty($app_row['appid']) ? (string) $app_row['appid'] : '';
        $status_text = ($new_status === Zibll_Oauth_App_DB::STATUS_APPROVED) ? '已通过' : '被驳回';

        $title = ($new_status === Zibll_Oauth_App_DB::STATUS_APPROVED) ? ('应用审核通过：' . $app_name) : ('应用审核驳回：' . $app_name);

        $message = '您好！' . $user->display_name . '<br>';
        $message .= '您提交的应用审核结果：' . $status_text . '<br>';
        $message .= '应用名称：' . esc_html($app_name) . '<br>';
        if ($appid !== '') {
            $message .= 'AppID：' . esc_html($appid) . '<br>';
        }
        // 审核通过时，在邮件中附带完整的 AppKey
        if ($new_status === Zibll_Oauth_App_DB::STATUS_APPROVED) {
            $appkey = !empty($app_row['appkey']) ? (string) $app_row['appkey'] : '';
            if ($appkey !== '') {
                $message .= 'AppKey：' . esc_html($appkey) . '<br>';
                $message .= '<b style="color:#e74c3c;">⚠️ 请妥善保存此密钥，它仅通过邮件发送一次，后续将无法再次查看完整密钥。</b><br>';
            }
        }
        $message .= '处理时间：' . esc_html(current_time('mysql')) . '<br>';
        if ($new_status === Zibll_Oauth_App_DB::STATUS_REJECTED && $reject_reason !== '') {
            $message .= '驳回原因：' . esc_html((string) $reject_reason) . '<br>';
        }

        if (class_exists('ZibMsg')) {
            $msg_args = array(
                'send_user' => 'admin',
                'receive_user' => $user_id,
                'type' => 'system',
                'title' => $title,
                'content' => $message,
            );
            ZibMsg::add($msg_args);
        }

        if (!empty($user->user_email) && is_email($user->user_email) && !stristr($user->user_email, '@no')) {
            @wp_mail($user->user_email, $title, $message);
        }
    }
}
