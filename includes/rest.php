<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Zibll_Oauth_Rest
{
    const REST_NAMESPACE = 'zibll-oauth/v1';

    public static function register_routes()
    {
        register_rest_route(self::REST_NAMESPACE, '/health', array(
            'methods'  => 'GET',
            'callback' => array(__CLASS__, 'health'),
            'permission_callback' => '__return_true',
        ));

        register_rest_route(self::REST_NAMESPACE, '/authorize', array(
            'methods'  => 'GET',
            'callback' => array('Zibll_Oauth_Service', 'authorize'),
            'permission_callback' => '__return_true',
        ));

        register_rest_route(self::REST_NAMESPACE, '/token', array(
            'methods'  => 'POST',
            'callback' => array('Zibll_Oauth_Service', 'token'),
            'permission_callback' => '__return_true',
        ));

        register_rest_route(self::REST_NAMESPACE, '/revoke', array(
            'methods'  => 'POST',
            'callback' => array('Zibll_Oauth_Service', 'revoke'),
            'permission_callback' => '__return_true',
        ));

        register_rest_route(self::REST_NAMESPACE, '/userinfo', array(
            'methods'  => 'GET',
            'callback' => array('Zibll_Oauth_Service', 'userinfo'),
            'permission_callback' => '__return_true',
        ));

        register_rest_route(self::REST_NAMESPACE, '/unionid', array(
            'methods'  => 'GET',
            'callback' => array('Zibll_Oauth_Service', 'unionid'),
            'permission_callback' => '__return_true',
        ));

        register_rest_route(self::REST_NAMESPACE, '/authorize_finance', array(
            'methods'  => 'GET',
            'callback' => array('Zibll_Oauth_Service', 'authorize_finance'),
            'permission_callback' => '__return_true',
        ));

        register_rest_route(self::REST_NAMESPACE, '/finance/deduct', array(
            'methods'  => 'POST',
            'callback' => array('Zibll_Oauth_Service', 'finance_deduct'),
            'permission_callback' => '__return_true',
        ));

		register_rest_route(self::REST_NAMESPACE, '/finance/verify', array(
			'methods'  => 'GET',
			'callback' => array('Zibll_Oauth_Service', 'finance_verify'),
			'permission_callback' => '__return_true',
		));

		register_rest_route(self::REST_NAMESPACE, '/finance/sign_status', array(
			'methods'  => 'GET',
			'callback' => array('Zibll_Oauth_Service', 'finance_sign_status'),
			'permission_callback' => '__return_true',
		));

		register_rest_route(self::REST_NAMESPACE, '/points/add', array(
			'methods'  => 'POST',
			'callback' => array('Zibll_Oauth_Points', 'add'),
			'permission_callback' => '__return_true',
		));

		register_rest_route(self::REST_NAMESPACE, '/points/balance', array(
			'methods'  => 'GET',
			'callback' => array('Zibll_Oauth_Points', 'balance'),
			'permission_callback' => '__return_true',
		));

		register_rest_route(self::REST_NAMESPACE, '/user/profile', array(
			'methods'  => 'GET',
			'callback' => array('Zibll_Oauth_Points', 'profile'),
			'permission_callback' => '__return_true',
		));

		register_rest_route(self::REST_NAMESPACE, '/user/bindtg', array(
			'methods'  => 'POST',
			'callback' => array('Zibll_Oauth_Usermeta', 'bindtg'),
			'permission_callback' => '__return_true',
		));

		register_rest_route(self::REST_NAMESPACE, '/user/tgbind', array(
			'methods'  => 'GET',
			'callback' => array('Zibll_Oauth_Usermeta', 'tgbind'),
			'permission_callback' => '__return_true',
		));

		register_rest_route(self::REST_NAMESPACE, '/user/unbindtg', array(
			'methods'  => 'POST',
			'callback' => array('Zibll_Oauth_Usermeta', 'unbindtg'),
			'permission_callback' => '__return_true',
		));
	}

    public static function health()
    {
        return new WP_REST_Response(array('ok' => true), 200);
    }
}
