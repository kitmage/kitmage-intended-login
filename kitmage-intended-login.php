<?php
/**
 * Plugin Name: Kitmage Intended Login
 * Description: Persists and honors intended front-end URLs across Force Login, WordPress login, FluentAuth, and FluentForms registration flows.
 * Version: 1.0.0
 * Author: Mike@KitMage
 * Author URI: https://kitmage.com
 * License: GPL-2.0-or-later
 * Text Domain: kitmage-intended-login
 */

if (!defined('ABSPATH')) {
    exit;
}

define('KITMAGE_INTENDED_COOKIE', 'kitmage_intended_path');
define('KITMAGE_INTENDED_TTL', 15 * MINUTE_IN_SECONDS);
define('KITMAGE_INTENDED_EXCLUSIONS_OPTION', 'kitmage_intended_exclusion_slugs');

/**
 * Sanitize an intended destination into a safe on-site path with optional query.
 *
 * @param mixed $value Candidate redirect destination.
 * @return string Safe relative path and query, or an empty string when invalid.
 */
function kitmage_sanitize_intended_path($value) {
    if (empty($value) || !is_string($value)) {
        return '';
    }

    $value = trim(wp_unslash($value));

    if (preg_match('~^https?://~i', $value)) {
        $host = parse_url($value, PHP_URL_HOST);
        $home_host = parse_url(home_url(), PHP_URL_HOST);

        if ($host && $home_host && strtolower($host) !== strtolower($home_host)) {
            return '';
        }

        $path = parse_url($value, PHP_URL_PATH) ?: '';
        $query = parse_url($value, PHP_URL_QUERY);
        $value = $path . ($query ? ('?' . $query) : '');
    }

    if (!str_starts_with($value, '/')) {
        $value = '/' . ltrim($value, '/');
    }

    $only_path = parse_url($value, PHP_URL_PATH) ?: $value;
    $lower_path = strtolower($only_path);
    $blocked_prefixes = [
        '/wp-login.php',
        '/wp-admin',
        '/wp-includes',
        '/wp-content',
    ];

    foreach ($blocked_prefixes as $prefix) {
        if (str_starts_with($lower_path, $prefix)) {
            return '';
        }
    }

    if (str_contains($lower_path, 'admin-ajax.php')) {
        return '';
    }

    if (kitmage_matches_intended_exclusion_slug($only_path)) {
        return '';
    }

    if (preg_match('~\.(png|jpg|jpeg|gif|svg|webp|ico|css|js|map|pdf|zip)$~i', $only_path)) {
        return '';
    }

    return esc_url_raw($value);
}

/**
 * Determine the cookie domain used for intended URL persistence.
 *
 * @return string Cookie domain.
 */
function kitmage_intended_cookie_domain() {
    return parse_url(home_url(), PHP_URL_HOST) ?: '';
}

/**
 * Set the intended destination cookie.
 *
 * @param string $path_value Safe relative path and query.
 */
function kitmage_set_intended_cookie($path_value) {
    setcookie(
        KITMAGE_INTENDED_COOKIE,
        $path_value,
        [
            'expires'  => time() + KITMAGE_INTENDED_TTL,
            'path'     => '/',
            'domain'   => kitmage_intended_cookie_domain(),
            'secure'   => is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]
    );

    $_COOKIE[KITMAGE_INTENDED_COOKIE] = $path_value;
}

/**
 * Clear the intended destination cookie.
 */
function kitmage_clear_intended_cookie() {
    setcookie(
        KITMAGE_INTENDED_COOKIE,
        '',
        [
            'expires'  => time() - HOUR_IN_SECONDS,
            'path'     => '/',
            'domain'   => kitmage_intended_cookie_domain(),
            'secure'   => is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]
    );

    unset($_COOKIE[KITMAGE_INTENDED_COOKIE]);
}

/**
 * Check whether a request URI should never be stored as an intended destination.
 *
 * @param string $uri Request URI.
 * @return bool
 */
function kitmage_is_excluded_intended_uri($uri) {
    $path = parse_url($uri, PHP_URL_PATH) ?: $uri;
    $path = '/' . ltrim(strtolower($path), '/');

    $excluded_prefixes = [
        '/wp-login.php',
        '/wp-admin',
        '/wp-includes',
        '/wp-content',
        '/register',
        '/continue',
        '/login',
    ];

    foreach ($excluded_prefixes as $prefix) {
        if (str_starts_with($path, $prefix)) {
            return true;
        }
    }

    if (str_contains($path, 'admin-ajax.php')) {
        return true;
    }

    return kitmage_matches_intended_exclusion_slug($path);
}

/**
 * Store intended path for logged-out GET requests to front-end pages.
 */
function kitmage_store_intended_path() {
    if (is_user_logged_in()) {
        return;
    }

    if (!empty($_GET['ff_landing']) || !empty($_GET['entry_confirmation'])) {
        return;
    }

    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
        return;
    }

    $uri = $_SERVER['REQUEST_URI'] ?? '';
    if (!$uri || kitmage_is_excluded_intended_uri($uri)) {
        return;
    }

    $intended = kitmage_sanitize_intended_path($uri);
    if ($intended) {
        kitmage_set_intended_cookie($intended);
    }
}
add_action('init', 'kitmage_store_intended_path');

/**
 * Get configured partial-match exclusion slugs.
 *
 * @return string[] Normalized exclusion slugs.
 */
function kitmage_get_intended_exclusion_slugs() {
    $raw_slugs = get_option(KITMAGE_INTENDED_EXCLUSIONS_OPTION, []);

    if (is_string($raw_slugs)) {
        $raw_slugs = preg_split('/[\r\n,]+/', $raw_slugs);
    }

    if (!is_array($raw_slugs)) {
        return [];
    }

    $slugs = [];
    foreach ($raw_slugs as $slug) {
        $slug = trim(wp_unslash((string) $slug));
        $slug = trim($slug, " \t\n\r\0\x0B/");

        if ($slug === '') {
            continue;
        }

        $slugs[] = strtolower(sanitize_text_field($slug));
    }

    return array_values(array_unique($slugs));
}

/**
 * Sanitize exclusion slugs before saving settings.
 *
 * @param mixed $value Submitted option value.
 * @return string[] Normalized exclusion slugs.
 */
function kitmage_sanitize_intended_exclusion_slugs($value) {
    if (!is_array($value)) {
        $value = preg_split('/[\r\n,]+/', (string) $value);
    }

    $sanitized = [];
    foreach ($value as $slug) {
        $slug = trim(wp_unslash((string) $slug));
        $slug = trim($slug, " \t\n\r\0\x0B/");

        if ($slug === '') {
            continue;
        }

        $sanitized[] = strtolower(sanitize_text_field($slug));
    }

    return array_values(array_unique($sanitized));
}

/**
 * Check if a URI or path matches a configured exclusion slug.
 *
 * @param string $uri URI, path, or URL to inspect.
 * @return bool Whether the URI should bypass this plugin's redirect system.
 */
function kitmage_matches_intended_exclusion_slug($uri) {
    if (!$uri || !is_string($uri)) {
        return false;
    }

    if (preg_match('~^https?://~i', $uri)) {
        $uri = parse_url($uri, PHP_URL_PATH) ?: '';
    }

    $path = parse_url($uri, PHP_URL_PATH) ?: $uri;
    $path = '/' . ltrim(strtolower(rawurldecode($path)), '/');

    foreach (kitmage_get_intended_exclusion_slugs() as $slug) {
        if (str_contains($path, strtolower($slug))) {
            return true;
        }
    }

    return false;
}


/**
 * Check whether the current request matches a configured exclusion slug.
 *
 * @return bool Whether the current request should bypass plugin URL rewrites.
 */
function kitmage_current_request_matches_intended_exclusion_slug() {
    return kitmage_matches_intended_exclusion_slug($_SERVER['REQUEST_URI'] ?? '');
}

/**
 * Register the settings page and option for custom exclusions.
 */
function kitmage_register_intended_settings() {
    register_setting(
        'kitmage_intended_login',
        KITMAGE_INTENDED_EXCLUSIONS_OPTION,
        [
            'type'              => 'array',
            'sanitize_callback' => 'kitmage_sanitize_intended_exclusion_slugs',
            'default'           => [],
        ]
    );

    add_settings_section(
        'kitmage_intended_exclusions_section',
        __('Exclusion Slugs', 'kitmage-intended-login'),
        'kitmage_intended_exclusions_section_callback',
        'kitmage-intended-login'
    );

    add_settings_field(
        'kitmage_intended_exclusion_slugs_field',
        __('Bypass slugs', 'kitmage-intended-login'),
        'kitmage_intended_exclusion_slugs_field_callback',
        'kitmage-intended-login',
        'kitmage_intended_exclusions_section'
    );
}
add_action('admin_init', 'kitmage_register_intended_settings');

/**
 * Add the Kitmage Intended Login settings submenu under Settings.
 */
function kitmage_add_intended_settings_page() {
    add_options_page(
        __('Kitmage Intended Login', 'kitmage-intended-login'),
        __('Kitmage Intended Login', 'kitmage-intended-login'),
        'manage_options',
        'kitmage-intended-login',
        'kitmage_render_intended_settings_page'
    );
}
add_action('admin_menu', 'kitmage_add_intended_settings_page');

/**
 * Explain the custom exclusions setting.
 */
function kitmage_intended_exclusions_section_callback() {
    echo '<p>' . esc_html__('Add one slug or partial path per line. If a request path contains any of these values, Kitmage Intended Login will not store it, redirect to it, or rewrite its login/register URLs. Force Login will also be bypassed for matching paths.', 'kitmage-intended-login') . '</p>';
}

/**
 * Render the exclusion slugs textarea.
 */
function kitmage_intended_exclusion_slugs_field_callback() {
    $value = implode("\n", kitmage_get_intended_exclusion_slugs());

    printf(
        '<textarea name="%1$s" id="%1$s" rows="8" cols="50" class="large-text code" placeholder="teams\nwc-memberships\nmember-registration">%2$s</textarea>',
        esc_attr(KITMAGE_INTENDED_EXCLUSIONS_OPTION),
        esc_textarea($value)
    );

    echo '<p class="description">' . esc_html__('Partial matches are supported. For example, “teams” matches /my-account/teams/register/ and /teams-for-memberships/.', 'kitmage-intended-login') . '</p>';
}

/**
 * Render the settings page.
 */
function kitmage_render_intended_settings_page() {
    if (!current_user_can('manage_options')) {
        return;
    }
    ?>
    <div class="wrap">
        <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
        <form action="options.php" method="post">
            <?php
            settings_fields('kitmage_intended_login');
            do_settings_sections('kitmage-intended-login');
            submit_button();
            ?>
        </form>
    </div>
    <?php
}

/**
 * Force register links to the public registration page and preserve redirect_to.
 *
 * @param string $register_url Default register URL.
 * @return string
 */
function kitmage_register_url($register_url) {
    if (kitmage_current_request_matches_intended_exclusion_slug()) {
        return $register_url;
    }

    $register = home_url('/register/');
    $candidate = $_REQUEST['redirect_to'] ?? ($_COOKIE[KITMAGE_INTENDED_COOKIE] ?? '');
    $path = kitmage_sanitize_intended_path($candidate);

    if ($path) {
        return add_query_arg('redirect_to', home_url($path), $register);
    }

    return $register;
}
add_filter('register_url', 'kitmage_register_url');

/**
 * Prefer requested redirects or the stored intended path after login.
 *
 * @param string   $redirect_to           Default redirect URL.
 * @param string   $requested_redirect_to Requested redirect URL.
 * @param WP_User  $user                  Logged-in user.
 * @return string
 */
function kitmage_login_redirect($redirect_to, $requested_redirect_to, $user) {
    $candidate = $requested_redirect_to ?: ($_REQUEST['redirect_to'] ?? '');
    $path = kitmage_sanitize_intended_path($candidate);

    if (!$path) {
        $path = kitmage_sanitize_intended_path($_COOKIE[KITMAGE_INTENDED_COOKIE] ?? '');
    }

    if ($path) {
        return home_url($path);
    }

    $fallback_path = kitmage_sanitize_intended_path($redirect_to);
    return $fallback_path ? home_url($fallback_path) : home_url('/');
}
add_filter('login_redirect', 'kitmage_login_redirect', 99999, 3);

/**
 * Consume the intended cookie from the /continue helper page.
 */
function kitmage_continue_redirect() {
    if (!is_page('continue')) {
        return;
    }

    $candidate = $_GET['redirect_to'] ?? '';
    $path = kitmage_sanitize_intended_path($candidate);

    if (!$path) {
        $path = kitmage_sanitize_intended_path($_COOKIE[KITMAGE_INTENDED_COOKIE] ?? '');
    }

    $target = $path ? home_url($path) : home_url('/');

    if (is_user_logged_in()) {
        kitmage_clear_intended_cookie();
        wp_safe_redirect($target);
        exit;
    }

    wp_safe_redirect(wp_login_url(home_url('/continue/')));
    exit;
}
add_action('template_redirect', 'kitmage_continue_redirect');

/**
 * Bypass Force Login for public authentication and FluentForms confirmation flows.
 *
 * @param bool   $bypass      Whether Force Login should be bypassed.
 * @param string $visited_url Visited URL.
 * @return bool
 */
function kitmage_forcelogin_bypass($bypass, $visited_url) {
    if (is_page('register') || is_page('continue') || is_page('login')) {
        return true;
    }

    if (!empty($_GET['ff_landing']) || !empty($_GET['entry_confirmation'])) {
        return true;
    }

    if (kitmage_matches_intended_exclusion_slug($visited_url)) {
        return true;
    }

    return $bypass;
}
add_filter('v_forcelogin_bypass', 'kitmage_forcelogin_bypass', 10, 2);

/**
 * Route WordPress login URLs to the public login page.
 *
 * @param string $login_url    Default login URL.
 * @param string $redirect     Redirect URL.
 * @param bool   $force_reauth Whether to force reauthentication.
 * @return string
 */
function kitmage_login_url($login_url, $redirect, $force_reauth) {
    if (kitmage_current_request_matches_intended_exclusion_slug()) {
        return $login_url;
    }

    return home_url('/login/');
}
add_filter('login_url', 'kitmage_login_url', 10, 3);

/**
 * Render a configurable registration button.
 *
 * @param array $atts Shortcode attributes.
 * @return string
 */
function kitmage_register_button_shortcode($atts) {
    $atts = shortcode_atts(
        [
            'text'  => 'Register',
            'class' => 'register-button',
            'url'   => home_url('/register/'),
        ],
        $atts,
        'register_button'
    );

    return sprintf(
        '<a href="%s" class="%s">%s</a>',
        esc_url($atts['url']),
        esc_attr($atts['class']),
        esc_html($atts['text'])
    );
}
add_shortcode('register_button', 'kitmage_register_button_shortcode');

/**
 * Render a logout link for the current user.
 *
 * @return string
 */
function kitmage_logout_link_shortcode() {
    if (!is_user_logged_in()) {
        return '';
    }

    $user = wp_get_current_user();
    $logout_url = wp_logout_url(home_url('/'));

    return sprintf(
        '<a href="%s">%s</a>',
        esc_url($logout_url),
        esc_html(sprintf(__('Logout: %s', 'kitmage-intended-login'), $user->display_name))
    );
}
add_shortcode('logout_link', 'kitmage_logout_link_shortcode');
