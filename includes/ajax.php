<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Zibll_Oauth_Ajax
{
    const NONCE_ACTION = 'zibll_oauth_uc';

    private static function send_ok($msg = '处理完成', $reload = 1, $extra = array())
    {
        $payload = array_merge(array(
            'error' => 0,
            'msg' => (string) $msg,
            'reload' => (int) $reload,
        ), is_array($extra) ? $extra : array());

        wp_send_json($payload);
    }

    private static function send_err($msg = '操作失败', $extra = array())
    {
        $payload = array_merge(array(
            'error' => 1,
            'msg' => (string) $msg,
        ), is_array($extra) ? $extra : array());

        wp_send_json($payload);
    }

    public static function init()
    {
        add_action('wp_ajax_zibll_oauth_my_apps', array(__CLASS__, 'ajax_my_apps'));
        add_action('wp_ajax_zibll_oauth_create_app', array(__CLASS__, 'ajax_create_app'));
        add_action('wp_ajax_zibll_oauth_update_app', array(__CLASS__, 'ajax_update_app'));
        add_action('wp_ajax_zibll_oauth_delete_app', array(__CLASS__, 'ajax_delete_app'));
        add_action('wp_ajax_zibll_oauth_submit_app', array(__CLASS__, 'ajax_submit_app'));
        add_action('wp_ajax_zibll_oauth_app_create', array(__CLASS__, 'ajax_create_app'));
        add_action('wp_ajax_zibll_oauth_app_update', array(__CLASS__, 'ajax_update_app'));
        add_action('wp_ajax_zibll_oauth_app_delete', array(__CLASS__, 'ajax_delete_app'));
        add_action('wp_ajax_zibll_oauth_app_submit', array(__CLASS__, 'ajax_submit_app'));
        add_action('wp_ajax_zibll_oauth_app_modal', array(__CLASS__, 'ajax_app_modal'));
        add_action('wp_ajax_zibll_oauth_app_submit_modal', array(__CLASS__, 'ajax_app_submit_modal'));
        add_action('wp_ajax_zibll_oauth_app_delete_confirm_modal', array(__CLASS__, 'ajax_app_delete_confirm_modal'));
        add_action('wp_ajax_zibll_oauth_app_delete_modal', array(__CLASS__, 'ajax_app_delete_modal'));
        add_action('wp_ajax_zibll_oauth_app_delete_secure', array(__CLASS__, 'ajax_app_delete_secure'));
        add_action('wp_ajax_zibll_oauth_upload_icon', array(__CLASS__, 'ajax_upload_icon'));
        add_action('wp_ajax_zibll_oauth_appkey_rotate_modal', array(__CLASS__, 'ajax_appkey_rotate_modal'));
        add_action('wp_ajax_zibll_oauth_appkey_rotate_secure', array(__CLASS__, 'ajax_appkey_rotate_secure'));
        add_action('wp_ajax_zibll_oauth_grant_list', array(__CLASS__, 'grant_list'));
        add_action('wp_ajax_zibll_oauth_revoke_grant', array(__CLASS__, 'ajax_revoke_grant'));
    }

    private static function tmp_icon_meta_key()
    {
        return 'zibll_oauth_tmp_icon_url';
    }

    private static function crop_attachment_to_square_url($attachment_id)
    {
        $attachment_id = (int) $attachment_id;
        if ($attachment_id <= 0) {
            return '';
        }

        $file = get_attached_file($attachment_id);
        if (!$file || !file_exists($file) || !function_exists('wp_get_image_editor')) {
            return '';
        }

        $editor = wp_get_image_editor($file);
        if (is_wp_error($editor)) {
            return '';
        }

        $size = $editor->get_size();
        $w = !empty($size['width']) ? (int) $size['width'] : 0;
        $h = !empty($size['height']) ? (int) $size['height'] : 0;
        if ($w <= 0 || $h <= 0) {
            return '';
        }

        if ($w === $h) {
            return (string) wp_get_attachment_url($attachment_id);
        }

        $side = min($w, $h);
        $src_x = (int) floor(($w - $side) / 2);
        $src_y = (int) floor(($h - $side) / 2);
        $cropped = $editor->crop($src_x, $src_y, $side, $side, $side, $side);
        if (is_wp_error($cropped)) {
            return '';
        }

        $dest_file = $editor->generate_filename('square');
        $saved = $editor->save($dest_file);
        if (is_wp_error($saved) || empty($saved['path'])) {
            return '';
        }

        $upload_dir = wp_upload_dir();
        if (empty($upload_dir['basedir']) || empty($upload_dir['baseurl'])) {
            return '';
        }

        $path = (string) $saved['path'];
        $basedir = rtrim((string) $upload_dir['basedir'], '/');
        if (strpos($path, $basedir) !== 0) {
            return '';
        }

        $rel = ltrim(str_replace($basedir, '', $path), '/');
        return rtrim((string) $upload_dir['baseurl'], '/') . '/' . $rel;
    }

    public static function ajax_upload_icon()
    {
        $user_id = self::require_login();
        self::require_developer($user_id);

        $nonce = isset($_POST['upload_image_nonce']) ? (string) $_POST['upload_image_nonce'] : '';
        if (!$nonce || !wp_verify_nonce($nonce, 'upload_image')) {
            self::send_err('安全验证失败，请稍候再试');
        }

        //开始上传
        if (function_exists('zib_php_upload')) {
            $img_id = zib_php_upload();
            if (!empty($img_id['error'])) {
                self::send_err(isset($img_id['msg']) ? (string) $img_id['msg'] : '上传失败');
            }
        } else {
            if (!function_exists('media_handle_upload')) {
                require_once ABSPATH . 'wp-admin/includes/media.php';
                require_once ABSPATH . 'wp-admin/includes/file.php';
                require_once ABSPATH . 'wp-admin/includes/image.php';
            }
            $img_id = media_handle_upload('file', 0);
            if (is_wp_error($img_id)) {
                self::send_err($img_id->get_error_message());
            }
        }

        $img_url = self::crop_attachment_to_square_url((int) $img_id);
        if (!$img_url) {
            $size = !empty($_REQUEST['size']) ? (string) $_REQUEST['size'] : 'thumbnail';
            $src = wp_get_attachment_image_src((int) $img_id, $size);
            $img_url = !empty($src[0]) ? (string) $src[0] : '';
        }
        if (!$img_url) {
            self::send_err('上传失败');
        }

        update_user_meta($user_id, self::tmp_icon_meta_key(), $img_url);

        self::send_ok('图片已上传', 0, array(
            'img_url' => $img_url,
            'no_preview_reset' => 1,
        ));
    }

    public static function ajax_app_submit_modal()
    {
        $user_id = self::require_login();
        self::require_developer($user_id);

        $nonce = isset($_REQUEST['nonce']) ? (string) $_REQUEST['nonce'] : '';
        self::verify_nonce($nonce);

        $id = isset($_REQUEST['id']) ? (int) $_REQUEST['id'] : 0;
        $row = $id > 0 ? Zibll_Oauth_App_DB::get_by_id($id) : null;
        if (!$row || (int) $row['user_id'] !== (int) $user_id) {
            echo '<div class="muted-2-color">应用不存在或无权限</div>';
            exit;
        }

        $site = Zibll_Oauth_App_DB::to_site_array($row);
        $ajaxurl = admin_url('admin-ajax.php');

        $mv_html = '';
        if (function_exists('zib_get_machine_verification_input')) {
            $mv_html = zib_get_machine_verification_input('zibll_oauth_app_submit', 'canvas_yz');
        }

        $html = '';
        $html .= '<div class="zib-widget"><div class="box-body">';
        $html .= '<div class="title-h-left"><b>提交审核</b></div>';
        $html .= '<div class="mb10">应用：<b>' . esc_html((string) $site['title']) . '</b></div>';
        $html .= '<div class="muted-2-color em09 mb10">提交后将进入待审核状态，需管理员审核通过后才可上线授权</div>';

        $html .= '<form class="mt15" method="post" action="' . esc_url($ajaxurl) . '">';
        $html .= $mv_html;
        $html .= '<input type="hidden" name="action" value="zibll_oauth_app_submit">';
        $html .= '<input type="hidden" name="nonce" value="' . esc_attr($nonce) . '">';
        $html .= '<input type="hidden" name="post_id" value="' . (int) $site['id'] . '">';
        $html .= '<div class="but-average modal-buts">';
        $html .= '<button type="button" class="but" data-dismiss="modal">取消</button>';
        $html .= '<button type="button" class="but c-blue wp-ajax-submit">确认提交审核</button>';
        $html .= '</div>';
        $html .= '</form>';
        $html .= '</div></div>';

        echo $html;
        exit;
    }

    public static function ajax_app_delete_confirm_modal()
    {
        $user_id = self::require_login();
        self::require_developer($user_id);

        $nonce = isset($_REQUEST['nonce']) ? (string) $_REQUEST['nonce'] : '';
        self::verify_nonce($nonce);

        $id = isset($_REQUEST['id']) ? (int) $_REQUEST['id'] : 0;
        $row = $id > 0 ? Zibll_Oauth_App_DB::get_by_id($id) : null;
        if (!$row || (int) $row['user_id'] !== (int) $user_id) {
            echo '<div class="muted-2-color">应用不存在或无权限</div>';
            exit;
        }

        $site = Zibll_Oauth_App_DB::to_site_array($row);
        $next = '';
        if (function_exists('zib_get_refresh_modal_link')) {
            $next = zib_get_refresh_modal_link(array(
                'tag' => 'a',
                'class' => 'but c-red btn-block',
                'text' => '继续删除（进入验证）',
                'data_class' => 'modal-mini',
                'height' => 520,
                'mobile_bottom' => true,
                'query_arg' => array(
                    'action' => 'zibll_oauth_app_delete_modal',
                    'id' => (int) $site['id'],
                    'nonce' => $nonce,
                ),
            ));
        }

        $html = '';
        $html .= '<div class="zib-widget"><div class="box-body">';
        $html .= '<div class="title-h-left"><b>确认删除</b></div>';
        $html .= '<div class="c-red mb10">确定要删除应用：' . esc_html((string) $site['title']) . ' 吗？</div>';
        $html .= '<div class="muted-2-color em09 mb15">下一步需要完成验证后才能删除</div>';
        $html .= $next ? $next : '<div class="muted-2-color">当前环境不支持拟态框</div>';
        $html .= '<button type="button" class="but btn-block mt10" data-dismiss="modal">取消</button>';
        $html .= '</div></div>';

        echo $html;
        exit;
    }

    private static function get_bound_phone($user_id)
    {
        $user_id = (int) $user_id;
        if ($user_id <= 0) {
            return '';
        }

        if (function_exists('zib_get_user_phone_number')) {
            $p = zib_get_user_phone_number($user_id, false);
            if (is_string($p) && trim($p) !== '') {
                return trim($p);
            }
        }

        $phone = (string) get_user_meta($user_id, 'phone_number', true);
        return trim((string) $phone);
    }

    private static function get_bound_email($user_id)
    {
        $user_id = (int) $user_id;
        if ($user_id <= 0) {
            return '';
        }
        $u = get_user_by('id', $user_id);

        $mail = ($u && isset($u->user_email)) ? (string) $u->user_email : '';
        $mail = trim($mail);
        if ($mail === '' || !is_email($mail) || stristr($mail, '@no')) {
            return '';
        }

        return $mail;
    }

    private static function require_login()
    {
        $uid = get_current_user_id();
        if (!$uid) {
            self::send_err('请先登录');
        }
        return (int) $uid;
    }

    private static function verify_nonce($nonce)
    {
        $nonce = (string) $nonce;
        if ($nonce === '' || !wp_verify_nonce($nonce, self::NONCE_ACTION)) {
            self::send_err('安全验证失败');
        }
    }

    private static function require_developer($user_id)
    {
        if (!Zibll_Oauth_Options::is_user_developer($user_id)) {
            self::send_err('您无此权限，权限申请需联系sunshijie@yungnet.cn');
        }
    }

    private static function sanitize_scope($scope)
    {
        if (is_array($scope)) {
            $scope = implode(' ', array_map('strval', $scope));
        }
        $scope = trim((string) $scope);
        if ($scope === '') {
            return 'basic';
        }
        $parts = preg_split('/[\s,]+/', $scope);
        $allow = array('basic' => true, 'email' => true, 'profile' => true, 'phone' => true);
        $out = array();
        foreach ($parts as $p) {
            $p = trim((string) $p);
            if ($p === '' || empty($allow[$p])) {
                continue;
            }
            $out[$p] = true;
        }
        if (empty($out)) {
            return 'basic';
        }
        return implode(' ', array_keys($out));
    }

    public static function ajax_my_apps()
    {
        $user_id = self::require_login();
        self::require_developer($user_id);

        self::verify_nonce(isset($_REQUEST['nonce']) ? (string) $_REQUEST['nonce'] : '');

        $items = array();
        $rows = Zibll_Oauth_App_DB::list_by_user($user_id, 50);
        foreach ($rows as $row) {
            $items[] = Zibll_Oauth_App_DB::to_site_array($row);
        }

        self::send_ok('ok', 0, array('items' => $items));
    }

    public static function ajax_create_app()
    {
        $user_id = self::require_login();
        self::require_developer($user_id);

        self::verify_nonce(isset($_POST['nonce']) ? (string) $_POST['nonce'] : '');

        $name = isset($_POST['title']) ? trim((string) $_POST['title']) : '';
        if ($name === '') {
            self::send_err('应用名称不能为空');
        }

        $icon = isset($_POST['icon']) ? trim((string) $_POST['icon']) : '';
        if ($icon === '') {
            $tmp_icon = (string) get_user_meta($user_id, self::tmp_icon_meta_key(), true);
            if ($tmp_icon !== '') {
                $icon = $tmp_icon;
                delete_user_meta($user_id, self::tmp_icon_meta_key());
            }
        }
        $redirect_uri = isset($_POST['redirect_uri']) ? trim((string) $_POST['redirect_uri']) : '';
        $default_scope = isset($_POST['default_scope']) ? $_POST['default_scope'] : '';

        if ($redirect_uri !== '' && class_exists('Zibll_Oauth_Provider_Util') && method_exists('Zibll_Oauth_Provider_Util', 'is_valid_redirect_uri')) {
            if (!Zibll_Oauth_Provider_Util::is_valid_redirect_uri($redirect_uri)) {
                self::send_err('回调地址 redirect_uri 格式错误');
            }
        }

        $default_scope = self::sanitize_scope($default_scope);

        $created = Zibll_Oauth_App_DB::create($user_id, $name, $icon, $redirect_uri, $default_scope);
        if (is_wp_error($created)) {
            self::send_err($created->get_error_message());
        }

        self::send_ok('创建成功', 1, array('id' => (int) $created['id'], 'hide_modal' => true));
    }

    public static function ajax_update_app()
    {
        $user_id = self::require_login();
        self::require_developer($user_id);

        self::verify_nonce(isset($_POST['nonce']) ? (string) $_POST['nonce'] : '');

        $id = isset($_POST['post_id']) ? (int) $_POST['post_id'] : 0;
        if ($id <= 0) {
            self::send_err('应用不存在');
        }

        $title = isset($_POST['title']) ? trim((string) $_POST['title']) : '';
        if ($title !== '') {
            $updated = Zibll_Oauth_App_DB::update_by_owner($id, $user_id, array('title' => $title));
            if (is_wp_error($updated)) {
                self::send_err($updated->get_error_message());
            }
        }

        $icon = isset($_POST['icon']) ? trim((string) $_POST['icon']) : null;
        if ($icon !== null && $icon === '') {
            $tmp_icon = (string) get_user_meta($user_id, self::tmp_icon_meta_key(), true);
            if ($tmp_icon !== '') {
                $icon = $tmp_icon;
                delete_user_meta($user_id, self::tmp_icon_meta_key());
            }
        }
        $redirect_uri = isset($_POST['redirect_uri']) ? trim((string) $_POST['redirect_uri']) : null;
        $default_scope = isset($_POST['default_scope']) ? $_POST['default_scope'] : null;
        $ip_whitelist = isset($_POST['ip_whitelist']) ? trim((string) $_POST['ip_whitelist']) : null;

        if ($redirect_uri !== null && $redirect_uri !== '' && class_exists('Zibll_Oauth_Provider_Util') && method_exists('Zibll_Oauth_Provider_Util', 'is_valid_redirect_uri')) {
            if (!Zibll_Oauth_Provider_Util::is_valid_redirect_uri($redirect_uri)) {
                self::send_err('回调地址 redirect_uri 格式错误');
            }
        }

        $fields = array();
        if ($icon !== null) {
            $fields['icon'] = $icon;
        }
        if ($redirect_uri !== null) {
            $fields['redirect_uri'] = $redirect_uri;
        }
        if ($default_scope !== null) {
            $fields['default_scope'] = self::sanitize_scope($default_scope);
        }
        if ($ip_whitelist !== null) {
            $fields['ip_whitelist'] = $ip_whitelist;
        }

        $can_use_finance = Zibll_Oauth_Options::is_user_finance_enabled($user_id);

        if (isset($_POST['finance_enabled']) && $can_use_finance) {
            $fields['finance_enabled'] = 1;
        } elseif ($can_use_finance) {
            $fields['finance_enabled'] = 0;
        }

        if ($can_use_finance) {
            $finance_callback_url = isset($_POST['finance_callback_url']) ? trim((string) $_POST['finance_callback_url']) : '';
            if (isset($fields['finance_enabled']) && $fields['finance_enabled'] && $finance_callback_url === '') {
                self::send_err('启用财务权限时，扣款签约回调地址为必填');
            }

            if ($finance_callback_url !== '' && class_exists('Zibll_Oauth_Provider_Util') && method_exists('Zibll_Oauth_Provider_Util', 'is_safe_callback_url')) {
                if (!Zibll_Oauth_Provider_Util::is_safe_callback_url($finance_callback_url)) {
                    self::send_err('扣款签约回调地址不安全或格式错误');
                }
            }
            $fields['finance_callback_url'] = $finance_callback_url;

            $finance_deduct_callback_url = isset($_POST['finance_deduct_callback_url']) ? trim((string) $_POST['finance_deduct_callback_url']) : '';
            if ($finance_deduct_callback_url !== '' && class_exists('Zibll_Oauth_Provider_Util') && method_exists('Zibll_Oauth_Provider_Util', 'is_safe_callback_url')) {
                if (!Zibll_Oauth_Provider_Util::is_safe_callback_url($finance_deduct_callback_url)) {
                    self::send_err('扣款结果回调地址不安全或格式错误');
                }
            }
            $fields['finance_deduct_callback_url'] = $finance_deduct_callback_url;

            $revoke_callback_url = isset($_POST['revoke_callback_url']) ? trim((string) $_POST['revoke_callback_url']) : '';

            if ($revoke_callback_url !== '' && class_exists('Zibll_Oauth_Provider_Util') && method_exists('Zibll_Oauth_Provider_Util', 'is_safe_callback_url')) {
                if (!Zibll_Oauth_Provider_Util::is_safe_callback_url($revoke_callback_url)) {
                    self::send_err('取消授权回调地址不安全或格式错误');
                }
            }
            $fields['revoke_callback_url'] = $revoke_callback_url;
        }

        $updated = Zibll_Oauth_App_DB::update_by_owner($id, $user_id, $fields);
        if (is_wp_error($updated)) {
            self::send_err($updated->get_error_message());
        }

        self::send_ok('保存成功，请提交审核后上线', 1, array('hide_modal' => true));
    }

    public static function ajax_delete_app()
    {
        $user_id = self::require_login();
        self::require_developer($user_id);

        self::verify_nonce(isset($_POST['nonce']) ? (string) $_POST['nonce'] : '');

        $id = isset($_POST['post_id']) ? (int) $_POST['post_id'] : 0;
        if ($id <= 0) {
            self::send_err('应用不存在');
        }

        $ok = Zibll_Oauth_App_DB::delete_by_owner($id, $user_id);
        if (is_wp_error($ok)) {
            self::send_err($ok->get_error_message());
        }

        self::send_ok('删除成功', 1);
    }

    public static function ajax_app_modal()
    {
        $user_id = self::require_login();
        self::require_developer($user_id);

        $nonce = isset($_REQUEST['nonce']) ? (string) $_REQUEST['nonce'] : '';
        self::verify_nonce($nonce);

        $id = isset($_REQUEST['id']) ? (int) $_REQUEST['id'] : 0;
        $row = $id > 0 ? Zibll_Oauth_App_DB::get_by_id($id) : null;
        if ($id > 0) {
            if (!$row || (int) $row['user_id'] !== (int) $user_id) {
                echo '<div class="muted-2-color">应用不存在或无权限</div>';
                exit;
            }
        }

        $site = $row ? Zibll_Oauth_App_DB::to_site_array($row) : array(
            'id' => 0,
            'title' => '',
            'icon' => '',
            'redirect_uri' => '',
            'default_scope' => 'basic',
        );

        $scopes = preg_split('/[\s,]+/', (string) $site['default_scope']);
        $scopes = array_filter(array_map('trim', (array) $scopes));
        $checked = function ($k) use ($scopes) {
            return in_array($k, $scopes, true) ? ' checked="checked"' : '';
        };

        $action = $site['id'] ? 'zibll_oauth_app_update' : 'zibll_oauth_app_create';

        $ajaxurl = admin_url('admin-ajax.php');

        $add_img = defined('ZIB_TEMPLATE_DIRECTORY_URI') ? (string) ZIB_TEMPLATE_DIRECTORY_URI . '/img/upload-add.svg' : '';
        $icon_url = !empty($site['icon']) ? (string) $site['icon'] : '';
        $icon_preview = $icon_url ? '<img class="fit-cover" src="' . esc_url($icon_url) . '">' : ($add_img ? '<img class="fit-cover" src="' . esc_url($add_img) . '">' : '<div class="muted-2-color">+</div>');
        $upload_image_nonce = function_exists('wp_create_nonce') ? wp_create_nonce('upload_image') : '';

        $current_user_id = get_current_user_id();
        $can_use_finance = Zibll_Oauth_Options::is_user_finance_enabled($current_user_id);
        $finance_checked = !empty($site['finance_enabled']) ? ' checked="checked"' : '';

        $html = '';
        $html .= '<div class="zib-widget"><div class="box-body">';
        $html .= '<div class="title-h-left"><b>' . ($site['id'] ? '编辑应用' : '创建应用') . '</b></div>';
        $html .= '<form class="mini-upload" method="post" action="' . esc_url($ajaxurl) . '">';
        $html .= '<input type="hidden" name="action" value="' . esc_attr($action) . '">';
        $html .= '<input type="hidden" name="nonce" value="' . esc_attr($nonce) . '">';
        if ($site['id']) {
            $html .= '<input type="hidden" name="post_id" value="' . (int) $site['id'] . '">';
        }
        $html .= '<div class="mb10"><div class="muted-2-color em09 mb6">应用名称</div><input class="form-control" name="title" value="' . esc_attr((string) $site['title']) . '"></div>';
        $html .= '<input type="hidden" name="icon" value="' . esc_attr($icon_url) . '">';
        $html .= '<div class="mb10">';
        $html .= '<div class="muted-2-color em09 mb6">应用图标</div>';
        $html .= '<div class="form-upload">';
        $html .= '<label style="width:100%;" class="pointer">';
        $html .= '<div class="preview oauth-app-icon upload-preview radius4" style="width: 140px;height: 140px;">' . $icon_preview . '</div>';
        $html .= '<input class="hide" type="file" zibupload="image_upload" data-preview=".preview.oauth-app-icon" accept="image/gif,image/jpeg,image/jpg,image/png" name="image_upload" action="image_upload">';
        $html .= '</label>';
        $html .= '<button type="button" zibupload="submit" auto-submit="true" class="hide" name="submit">上传</button>';
        $html .= '<input type="hidden" data-name="action" data-value="zibll_oauth_upload_icon">';
        $html .= '<input type="hidden" data-name="upload_image_nonce" data-value="' . esc_attr($upload_image_nonce) . '">';
        $html .= '</div>';
        $html .= '</div>';
        $html .= '<div class="mb10"><div class="muted-2-color em09 mb6">回调地址 redirect_uri</div><input class="form-control" name="redirect_uri" value="' . esc_attr((string) $site['redirect_uri']) . '"></div>';
        $html .= '<div class="mb10"><div class="muted-2-color em09 mb6">接口请求 IP 白名单（可选）</div>';
        $html .= '<textarea class="form-control" name="ip_whitelist" rows="3" placeholder="每行一个 IP，例如：&#10;127.0.0.1&#10;192.168.1.10">' . esc_textarea((string) $site['ip_whitelist']) . '</textarea>';
        $html .= '<p class="muted-2-color em09 mt6">仅对 `/token`、`/userinfo`、`/unionid`、`/finance/*` 等服务端接口生效，未配置则不限制。</p>';
        $html .= '</div>';
        $html .= '<div class="mb10"><div class="muted-2-color em09 mb6">授权范围 scope</div>';
        $html .= '<label class="mr10"><input type="checkbox" name="default_scope[]" value="basic"' . $checked('basic') . '> basic</label>';
        $html .= '<label class="mr10"><input type="checkbox" name="default_scope[]" value="email"' . $checked('email') . '> email</label>';
        $html .= '<label class="mr10"><input type="checkbox" name="default_scope[]" value="profile"' . $checked('profile') . '> profile</label>';
        $html .= '<label class="mr10"><input type="checkbox" name="default_scope[]" value="phone"' . $checked('phone') . '> phone</label>';
        $html .= '</div>';

        if ($can_use_finance) {
            $html .= '<div class="mb10"><div class="muted-2-color em09 mb6">财务权限</div>';
            $html .= '<label class="mr10"><input type="checkbox" name="finance_enabled" value="1"' . $finance_checked . ' data-finance-toggle> 启用财务接口（免密支付）</label>';
            $html .= '</div>';
            $html .= '<div class="mb10 finance-callback-box" style="' . ($finance_checked ? '' : 'display:none;') . '">';
            $html .= '<div class="muted-2-color em09 mb6">扣款签约回调地址（必填）</div>';
            $html .= '<input class="form-control" name="finance_callback_url" value="' . esc_attr((string) $site['finance_callback_url']) . '" placeholder="https://example.com/callback">';
            $html .= '</div>';
            $html .= '<div class="mb10 finance-callback-box" style="' . ($finance_checked ? '' : 'display:none;') . '">';
            $html .= '<div class="muted-2-color em09 mb6">扣款结果回调地址（选填）</div>';
            $html .= '<input class="form-control" name="finance_deduct_callback_url" value="' . esc_attr((string) $site['finance_deduct_callback_url']) . '" placeholder="https://example.com/deduct-notify">';
            $html .= '</div>';
            $html .= '<div class="mb10">';
            $html .= '<div class="muted-2-color em09 mb6">取消授权回调地址（选填）</div>';
            $html .= '<input class="form-control" name="revoke_callback_url" value="' . esc_attr((string) $site['revoke_callback_url']) . '" placeholder="https://example.com/revoke-callback">';
            $html .= '</div>';
        }

        $html .= '<div class="but-average modal-buts">';
        $html .= '<button type="button" class="but" data-dismiss="modal">取消</button>';
        $html .= '<button type="button" class="but c-blue wp-ajax-submit">保存</button>';
        $html .= '</div>';
        $html .= '</form>';
        $html .= '</div></div>';

        if ($can_use_finance) {
            $html .= '<script>
            (function($){
                $(document).on("change", "[data-finance-toggle]", function(){
                    var checked = $(this).is(":checked");
                    $(".finance-callback-box").toggle(checked);
                    if(checked){
                        $("input[name=finance_callback_url]").attr("required", "required");
                    }else{
                        $("input[name=finance_callback_url]").removeAttr("required");
                    }
                });
                if($("[data-finance-toggle]").is(":checked")){
                    $("input[name=finance_callback_url]").attr("required", "required");
                }
            })(jQuery);
            </script>';
        }

        echo $html;
        exit;
    }

    public static function ajax_app_delete_modal()
    {
        $user_id = self::require_login();
        self::require_developer($user_id);

        $nonce = isset($_REQUEST['nonce']) ? (string) $_REQUEST['nonce'] : '';
        self::verify_nonce($nonce);

        $id = isset($_REQUEST['id']) ? (int) $_REQUEST['id'] : 0;
        $row = $id > 0 ? Zibll_Oauth_App_DB::get_by_id($id) : null;
        if (!$row || (int) $row['user_id'] !== (int) $user_id) {
            echo '<div class="muted-2-color">应用不存在或无权限</div>';
            exit;
        }

        $site = Zibll_Oauth_App_DB::to_site_array($row);
        $ajaxurl = admin_url('admin-ajax.php');

        $mv_html = '';
        if (function_exists('zib_get_machine_verification_input')) {
            $mv_html = zib_get_machine_verification_input('img_yz_zibll_oauth_app_delete');
        }

        $html = '';
        $html .= '<div class="zib-widget"><div class="box-body">';
        $html .= '<div class="title-h-left"><b>删除应用</b></div>';
        $html .= '<div class="c-red mb10">确定要删除应用：' . esc_html((string) $site['title']) . ' 吗？</div>';
        $html .= '<div class="muted-2-color em09 mb10">删除后不可恢复</div>';

        $html .= '<div class="mt10">';
        $html .= '<div class="muted-2-color em09 mb6">请输入登录密码验证</div>';
        $html .= '<form method="post" action="' . esc_url($ajaxurl) . '">';
        $html .= $mv_html;
        $html .= '<input type="hidden" name="action" value="zibll_oauth_app_delete_secure">';
        $html .= '<input type="hidden" name="nonce" value="' . esc_attr($nonce) . '">';
        $html .= '<input type="hidden" name="post_id" value="' . (int) $site['id'] . '">';
        $html .= '<input type="hidden" name="verify_type" value="password">';
        $html .= '<input type="password" class="form-control" name="password" value="" placeholder="登录密码">';
        $html .= '<div class="but-average modal-buts mt10">';
        $html .= '<button type="button" class="but" data-dismiss="modal">取消</button>';
        $html .= '<button type="button" class="but c-red wp-ajax-submit">确认删除</button>';
        $html .= '</div>';
        $html .= '</form>';
        $html .= '</div>';

        $html .= '</div></div>';

        echo $html;
        exit;
    }

    public static function ajax_app_delete_secure()
    {
        $user_id = self::require_login();
        self::require_developer($user_id);

        self::verify_nonce(isset($_POST['nonce']) ? (string) $_POST['nonce'] : '');

        if (function_exists('zib_ajax_man_machine_verification')) {
            zib_ajax_man_machine_verification('img_yz_zibll_oauth_app_delete');
        }

        $id = isset($_POST['post_id']) ? (int) $_POST['post_id'] : 0;
        if ($id <= 0) {
            self::send_err('应用不存在');
        }

        $password = isset($_POST['password']) ? (string) $_POST['password'] : '';
        if ($password === '') {
            self::send_err('请输入登录密码验证');
        }

        $u = get_user_by('id', $user_id);
        if (!$u) {
            self::send_err('用户不存在');
        }
        if (!wp_check_password($password, $u->user_pass, $user_id)) {
            self::send_err('密码错误');
        }

        $ok = Zibll_Oauth_App_DB::delete_by_owner($id, $user_id);
        if (is_wp_error($ok)) {
            self::send_err($ok->get_error_message());
        }

        self::send_ok('删除成功', 1, array('hide_modal' => true));
    }

    public static function ajax_appkey_rotate_modal()
    {
        $user_id = self::require_login();
        self::require_developer($user_id);

        $nonce = isset($_REQUEST['nonce']) ? (string) $_REQUEST['nonce'] : '';
        self::verify_nonce($nonce);

        $id = isset($_REQUEST['id']) ? (int) $_REQUEST['id'] : 0;
        $row = $id > 0 ? Zibll_Oauth_App_DB::get_by_id($id) : null;
        if (!$row || (int) $row['user_id'] !== (int) $user_id) {
            echo '<div class="muted-2-color">应用不存在或无权限</div>';
            exit;
        }

        $site = Zibll_Oauth_App_DB::to_site_array($row);
        $ajaxurl = admin_url('admin-ajax.php');

        $phone = self::get_bound_phone($user_id);
        $email = self::get_bound_email($user_id);

        $default_type = 'password';

        $mv_html = '';
        if (function_exists('zib_get_machine_verification_input')) {
            $mv_html = zib_get_machine_verification_input('img_yz_zibll_oauth_appkey_rotate');
        }

        $html = '';
        $html .= '<div class="zib-widget"><div class="box-body">';
        $html .= '<div class="title-h-left"><b>轮转密钥</b></div>';
        $html .= '<div class="mb10">应用：<b>' . esc_html((string) $site['title']) . '</b></div>';
        $html .= '<div class="c-red mb10">轮转后原密钥将立刻不可使用，请及时更新调用方配置</div>';
        $html .= '<div class="muted-2-color em09 mb10">轮转成功后，新密钥将发送至站内信和邮件（不在页面直接展示）</div>';
        $html .= '<div class="mt10">';
        $html .= '<div class="muted-2-color em09 mb6">请输入登录密码验证</div>';
        $html .= '<form method="post" action="' . esc_url($ajaxurl) . '">';
        $html .= $mv_html;
        $html .= '<input type="hidden" name="action" value="zibll_oauth_appkey_rotate_secure">';
        $html .= '<input type="hidden" name="nonce" value="' . esc_attr($nonce) . '">';
        $html .= '<input type="hidden" name="post_id" value="' . (int) $site['id'] . '">';
        $html .= '<input type="hidden" name="verify_type" value="password">';
        $html .= '<input type="password" class="form-control" name="password" value="" placeholder="登录密码">';
        $html .= '<div class="but-average modal-buts mt10">';
        $html .= '<button type="button" class="but" data-dismiss="modal">取消</button>';
        $html .= '<button type="button" class="but c-yellow wp-ajax-submit">确认轮转</button>';
        $html .= '</div>';
        $html .= '</form>';
        $html .= '</div>';

        $html .= '</div></div>';

        echo $html;
        exit;
    }

    public static function ajax_appkey_rotate_secure()
    {
        $user_id = self::require_login();
        self::require_developer($user_id);

        self::verify_nonce(isset($_POST['nonce']) ? (string) $_POST['nonce'] : '');

        $id = isset($_POST['post_id']) ? (int) $_POST['post_id'] : 0;
        if ($id <= 0) {
            self::send_err('应用不存在');
        }

        if (function_exists('zib_ajax_man_machine_verification')) {
            zib_ajax_man_machine_verification('img_yz_zibll_oauth_appkey_rotate');
        }

        $password = isset($_POST['password']) ? (string) $_POST['password'] : '';
        if ($password === '') {
            self::send_err('请输入登录密码验证');
        }
        $u = get_user_by('id', $user_id);
        if (!$u) {
            self::send_err('用户不存在');
        }
        if (!wp_check_password($password, $u->user_pass, $user_id)) {
            self::send_err('密码错误');
        }

        $new_key = Zibll_Oauth_App_DB::rotate_appkey_by_owner($id, $user_id);
        if (is_wp_error($new_key)) {
            self::send_err($new_key->get_error_message());
        }

        $app_row = Zibll_Oauth_App_DB::get_by_id($id);
        $app_name = $app_row && !empty($app_row['title']) ? (string) $app_row['title'] : '';
        $appid = $app_row && !empty($app_row['appid']) ? (string) $app_row['appid'] : '';

        $title = '应用密钥已轮转：' . $app_name;
        $message = '您好！<br>';
        $message .= '您的应用密钥已成功轮转（原密钥已立刻失效）<br>';
        if ($app_name !== '') {
            $message .= '应用名称：' . esc_html($app_name) . '<br>';
        }
        if ($appid !== '') {
            $message .= 'AppID：' . esc_html($appid) . '<br>';
        }
        $message .= '新 AppKey：' . esc_html((string) $new_key) . '<br>';
        $message .= '请尽快在调用方更新配置<br>';
        $message .= '操作时间：' . esc_html(current_time('mysql')) . '<br>';

        if (class_exists('ZibMsg')) {
            ZibMsg::add(array(
                'send_user' => 'admin',
                'receive_user' => $user_id,
                'type' => 'system',
                'title' => $title,
                'content' => $message,
            ));
        }
        $u = get_user_by('id', $user_id);
        if ($u && !empty($u->user_email) && is_email($u->user_email) && !stristr($u->user_email, '@no')) {
            @wp_mail($u->user_email, $title, $message);
        }

        self::send_ok('轮转成功，新密钥已通过站内信和邮件发送', 1, array(
            'hide_modal' => true,
        ));
    }

    public static function ajax_submit_app()
    {
        $user_id = self::require_login();
        self::require_developer($user_id);

        self::verify_nonce(isset($_POST['nonce']) ? (string) $_POST['nonce'] : '');

        if (function_exists('zib_ajax_man_machine_verification')) {
            zib_ajax_man_machine_verification('zibll_oauth_app_submit');
        }

        $id = isset($_POST['post_id']) ? (int) $_POST['post_id'] : 0;
        if ($id <= 0) {
            self::send_err('应用不存在');
        }

        $submitted = Zibll_Oauth_App_DB::submit($id, $user_id);
        if (is_wp_error($submitted)) {
            self::send_err($submitted->get_error_message());
        }

        self::send_ok('提交成功，等待审核', 1, array('hide_modal' => true));
    }

    public static function grant_list()
    {
        $user_id = self::require_login();

        self::verify_nonce(isset($_REQUEST['nonce']) ? (string) $_REQUEST['nonce'] : '');

        $rows = Zibll_Oauth_Grant::list_active_by_user($user_id, 50);

        $items = array();
        foreach ((array) $rows as $r) {
            $appid = !empty($r['appid']) ? (string) $r['appid'] : '';
            $app_row = $appid ? Zibll_Oauth_App_DB::find_by_appid($appid) : null;
            $site = $app_row ? Zibll_Oauth_App_DB::to_site_array($app_row) : null;

            $items[] = array(
                'appid' => $appid,
                'title' => $site ? (string) $site['title'] : '',
                'app_icon' => $site ? (string) $site['icon'] : '',
                'created_at' => !empty($r['created_at']) ? (string) $r['created_at'] : '',
            );
        }

        self::send_ok('ok', 0, array('items' => $items));
    }

    /**
     * 取消某个应用的授权（包含财务权限），并触发异步回调
     *
     * - 入口：前台用户中心「授权记录」中的“取消授权”按钮
     * - 行为：
     *   1. 将授权记录标记为失效（status=0）
     *   2. 触发应用配置的 revoke_callback_url（如有），以 HMAC-SHA256 sign 回调
     */
    public static function ajax_revoke_grant()
    {
        $user_id = self::require_login();

        self::verify_nonce(isset($_POST['nonce']) ? (string) $_POST['nonce'] : '');

        $appid = isset($_POST['appid']) ? trim((string) $_POST['appid']) : '';
        if ($appid === '') {
            self::send_err('缺少 AppID');
        }

        // 确认曾授权
        $grant = Zibll_Oauth_Grant::get_by_appid_user($appid, $user_id);
        if (!$grant || (int) $grant['status'] !== 1) {
            self::send_err('当前应用未处于已授权状态');
        }

        // 撤销授权记录
        $ok = Zibll_Oauth_Grant::revoke_grant($appid, $user_id);
        if (!$ok) {
            self::send_err('取消授权失败，请稍后重试');
        }

        if (class_exists('Zibll_Oauth_Service') && method_exists('Zibll_Oauth_Service', 'revoke_user_tokens')) {
            Zibll_Oauth_Service::revoke_user_tokens($appid, $user_id);
        }

        if (function_exists('wp_cache_delete')) {
            $ck = 'grants:user:' . (int) $user_id;
            wp_cache_delete($ck, 'zibll_oauth');
            wp_cache_delete($ck . '_active', 'zibll_oauth');
            wp_cache_delete($ck);
            wp_cache_delete($ck . '_active');
        }

        if (class_exists('Zibll_Oauth_Admin_Log') && method_exists('Zibll_Oauth_Admin_Log', 'add_log')) {
            Zibll_Oauth_Admin_Log::add_log($appid, $user_id, 'revoke_grant', '用户在授权记录中取消授权');
        }

        // 异步通知应用（如配置了取消授权回调）
        $app_row = Zibll_Oauth_App_DB::find_by_appid($appid);
        if ($app_row) {
            $site = Zibll_Oauth_App_DB::to_site_array($app_row);
            $callback_url = !empty($site['revoke_callback_url']) ? (string) $site['revoke_callback_url'] : '';
            $appkey = !empty($site['appkey']) ? (string) $site['appkey'] : '';

            if ($callback_url !== '' && $appkey !== '' && function_exists('wp_remote_post') && class_exists('Zibll_Oauth_Provider_Util') && method_exists('Zibll_Oauth_Provider_Util', 'is_safe_callback_url') && Zibll_Oauth_Provider_Util::is_safe_callback_url($callback_url)) {
                $openid = Zibll_Oauth_Provider_Util::get_openid($user_id, $appid);

                $finance_granted = !empty($grant['finance_scope']) && (int) $grant['finance_scope'] === 1;

                $payload = array(
                    'appid' => $appid,
                    'openid' => $openid,
                    'user_id' => $user_id,
                    'finance_granted' => $finance_granted ? 1 : 0,
                    'status' => 'revoked',
                    'revoked_at' => time(),
                );

                if (class_exists('Zibll_Oauth_Service') && method_exists('Zibll_Oauth_Service', 'finalize_callback_payload')) {
                    $payload = Zibll_Oauth_Service::finalize_callback_payload($payload, $appkey);
                }

                $dedupe_key = 'zibll_oauth_cb_' . md5('revoke|' . (string) $appid . '|' . (string) ($payload['event_id'] ?? ''));

                if (!get_transient($dedupe_key)) {
                    set_transient($dedupe_key, 1, DAY_IN_SECONDS);
                    if (class_exists('Zibll_Oauth_Service') && method_exists('Zibll_Oauth_Service', 'schedule_callback_send')) {
                        Zibll_Oauth_Service::schedule_callback_send($callback_url, $payload);
                    } else {
                        wp_remote_post($callback_url, array(
                            'body' => wp_json_encode($payload),
                            'timeout' => 5,
                            'redirection' => 0,
                            'reject_unsafe_urls' => true,
                            'headers' => array(
                                'Content-Type' => 'application/json',
                                'Accept' => 'application/json',
                            ),
                        ));
                    }
                }
            }
        }

        $goto = '';

        if (function_exists('home_url') && function_exists('wp_parse_url') && !empty($_SERVER['HTTP_REFERER'])) {
            $ref = (string) $_SERVER['HTTP_REFERER'];
            $home = (string) home_url('/');
            $rh = wp_parse_url($ref, PHP_URL_HOST);
            $hh = wp_parse_url($home, PHP_URL_HOST);
            if ($rh && $hh && strtolower((string) $rh) === strtolower((string) $hh)) {
                $goto = $ref;
            }
        }
        if ($goto !== '' && function_exists('add_query_arg')) {
            $goto = (string) add_query_arg('zibll_oauth_ts', (string) time(), $goto);
        }

        self::send_ok('已取消授权', 1, array(
            'hide_modal' => true,
            'msg' => '已取消授权，页面即将刷新',
            'goto' => $goto,
        ));
    }
}
