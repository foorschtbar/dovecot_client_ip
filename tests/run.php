<?php

error_reporting(E_ALL);

set_error_handler(function ($severity, $message, $file, $line) {
    throw new ErrorException($message, 0, $severity, $file, $line);
});

class TestConfig
{
    private $values = [];

    public function __construct($values = [])
    {
        $this->values = $values;
    }

    public function get($key)
    {
        return isset($this->values[$key]) ? $this->values[$key] : null;
    }

    public function set($key, $value)
    {
        $this->values[$key] = $value;
    }
}

class rcmail
{
    public static $instance;

    public $config;

    public static function get_instance()
    {
        return self::$instance;
    }
}

class rcube_plugin
{
    public function load_config()
    {
    }

    public function add_hook($name, $callback)
    {
    }
}

if (!defined('RCMAIL_VERSION')) {
    define('RCMAIL_VERSION', '1.7.2');
}

if (!function_exists('version_parse')) {
    function version_parse($version)
    {
        return $version;
    }
}

require dirname(__DIR__) . '/dovecot_client_ip.php';

class TestableDovecotClientIp extends dovecot_client_ip
{
    public function resolveClientIp()
    {
        return $this->get_client_ip();
    }

    public function loadEnvironmentConfig()
    {
        $this->load_env_config();
    }
}

$tests = [];

function test_case($name, $callback)
{
    global $tests;
    $tests[$name] = $callback;
}

function assert_same($expected, $actual, $message)
{
    if ($expected !== $actual) {
        throw new RuntimeException(
            $message . ' Expected ' . var_export($expected, true) . ', got ' . var_export($actual, true) . '.'
        );
    }
}

function assert_true($actual, $message)
{
    assert_same(true, $actual, $message);
}

function assert_false($actual, $message)
{
    assert_same(false, $actual, $message);
}

function request_from($remote_addr, $headers = [])
{
    $_SERVER = [];

    if ($remote_addr !== null) {
        $_SERVER['REMOTE_ADDR'] = $remote_addr;
    }

    foreach ($headers as $name => $value) {
        $_SERVER[$name] = $value;
    }
}

function plugin_with_config($trusted_proxies = [], $allow_private = false)
{
    rcmail::$instance = new rcmail();
    rcmail::$instance->config = new TestConfig([
        dovecot_client_ip::TrustedProxiesConfigKey => $trusted_proxies,
        dovecot_client_ip::ProxyAllowPrivateClientIpConfigKey => $allow_private,
    ]);

    $plugin = new TestableDovecotClientIp();
    $plugin->init();

    return $plugin;
}

test_case('CIDR matches exact IPv4 and IPv6 addresses', function () {
    assert_true(dovecot_client_ip\CIDR::match('192.0.2.10', '192.0.2.10'), 'Exact IPv4 match');
    assert_true(dovecot_client_ip\CIDR::match('2001:db8::1', '2001:0db8:0:0::1'), 'Exact IPv6 match');
    assert_false(dovecot_client_ip\CIDR::match('192.0.2.10', '192.0.2.11'), 'Different IPv4 address');
});

test_case('CIDR matches valid IPv4 masks including non-byte boundaries', function () {
    assert_true(dovecot_client_ip\CIDR::match('203.0.113.200', '203.0.113.128/25'), 'IPv4 /25 match');
    assert_false(dovecot_client_ip\CIDR::match('203.0.113.127', '203.0.113.128/25'), 'IPv4 /25 miss');
    assert_true(dovecot_client_ip\CIDR::match('203.0.113.10', '0.0.0.0/0'), 'IPv4 /0 match');
    assert_true(dovecot_client_ip\CIDR::match('203.0.113.10', '203.0.113.10/32'), 'IPv4 /32 match');
});

test_case('CIDR matches valid IPv6 masks including non-byte boundaries', function () {
    assert_true(dovecot_client_ip\CIDR::match('2001:db8:0:0:4000::1', '2001:db8::/65'), 'IPv6 /65 match');
    assert_false(dovecot_client_ip\CIDR::match('2001:db8:0:0:8000::1', '2001:db8::/65'), 'IPv6 /65 miss');
    assert_true(dovecot_client_ip\CIDR::match('2606:4700:4700::1111', '::/0'), 'IPv6 /0 match');
    assert_true(dovecot_client_ip\CIDR::match('2606:4700:4700::1111', '2606:4700:4700::1111/128'), 'IPv6 /128 match');
});

test_case('CIDR rejects invalid networks without warnings or exceptions', function () {
    $invalid_networks = [
        '',
        ' ',
        'garbage',
        'not-an-ip/0',
        '192.0.2.1/',
        '/24',
        '192.0.2.1/33',
        '2001:db8::1/129',
        '192.0.2.1/-1',
        '192.0.2.1/1.5',
        '192.0.2.1/foo',
        '192.0.2.1/24/1',
        '192.0.2.*',
        '2001:db8:*',
        null,
        [],
    ];

    foreach ($invalid_networks as $network) {
        assert_false(dovecot_client_ip\CIDR::match('203.0.113.10', $network), 'Invalid network match');
        assert_false(dovecot_client_ip\CIDR::isValidNetwork($network), 'Invalid network validation');
    }

    assert_false(dovecot_client_ip\CIDR::match('garbage', 'garbage'), 'Invalid exact address match');
    assert_false(dovecot_client_ip\CIDR::match('192.0.2.1', '2001:db8::/32'), 'Mixed address families');
});

test_case('direct requests ignore spoofed forwarding headers', function () {
    request_from('8.8.8.8', [
        'HTTP_CLIENT_IP' => '46.148.158.142',
        'HTTP_X_FORWARDED_FOR' => '46.148.158.142',
    ]);

    assert_same('8.8.8.8', plugin_with_config()->resolveClientIp(), 'Direct client address');
});

test_case('missing or invalid REMOTE_ADDR fails closed', function () {
    $plugin = plugin_with_config();

    request_from(null);
    assert_same(null, $plugin->resolveClientIp(), 'Missing REMOTE_ADDR');

    request_from('');
    assert_same(null, $plugin->resolveClientIp(), 'Empty REMOTE_ADDR');

    request_from('garbage');
    assert_same(null, $plugin->resolveClientIp(), 'Invalid REMOTE_ADDR');

    request_from([]);
    assert_same(null, $plugin->resolveClientIp(), 'Non-string REMOTE_ADDR');
});

test_case('invalid trusted proxy entries never enable forwarded headers', function () {
    request_from('8.8.8.8', [
        'HTTP_CLIENT_IP' => '46.148.158.142',
        'HTTP_X_FORWARDED_FOR' => '46.148.158.142',
    ]);

    $plugin = plugin_with_config(['', 'garbage', 'not-an-ip/0']);
    assert_same('8.8.8.8', $plugin->resolveClientIp(), 'Invalid trusted proxy entries');
});

test_case('trusted proxy resolves X-Forwarded-For from the right', function () {
    request_from('10.0.0.1', [
        'HTTP_X_FORWARDED_FOR' => '46.148.158.142, 8.8.8.8, 10.0.0.2',
    ]);

    $plugin = plugin_with_config(['10.0.0.0/8']);
    assert_same('8.8.8.8', $plugin->resolveClientIp(), 'Rightmost untrusted X-Forwarded-For address');
});

test_case('trusted proxy ignores unsupported spoofable headers', function () {
    request_from('10.0.0.1', [
        'HTTP_CLIENT_IP' => '46.148.158.142',
        'HTTP_X_REAL_IP' => '46.148.158.142',
        'HTTP_X_FORWARDED_FOR' => '8.8.8.8',
    ]);

    assert_same('8.8.8.8', plugin_with_config(['10.0.0.0/8'])->resolveClientIp(), 'Unsupported headers');
});

test_case('trusted proxy without a supported header fails closed', function () {
    request_from('10.0.0.1');

    assert_same(null, plugin_with_config(['10.0.0.0/8'])->resolveClientIp(), 'Missing forwarding chain');
});

test_case('trusted proxy rejects malformed and incomplete chains', function () {
    $plugin = plugin_with_config(['10.0.0.0/8']);

    request_from('10.0.0.1', ['HTTP_X_FORWARDED_FOR' => '8.8.8.8,']);
    assert_same(null, $plugin->resolveClientIp(), 'Malformed X-Forwarded-For chain');

    request_from('10.0.0.1', ['HTTP_X_FORWARDED_FOR' => '10.0.0.2']);
    assert_same(null, $plugin->resolveClientIp(), 'All-trusted X-Forwarded-For chain');

    request_from('10.0.0.1', ['HTTP_FORWARDED' => 'for=unknown']);
    assert_same(null, $plugin->resolveClientIp(), 'Unknown Forwarded value');

    request_from('10.0.0.1', ['HTTP_FORWARDED' => 'for=_hidden']);
    assert_same(null, $plugin->resolveClientIp(), 'Obfuscated Forwarded value');

    request_from('10.0.0.1', ['HTTP_FORWARDED' => 'for=8.8.8.8;for=1.1.1.1']);
    assert_same(null, $plugin->resolveClientIp(), 'Duplicate Forwarded for parameter');

    request_from('10.0.0.1', ['HTTP_FORWARDED' => 'for="8.8.8.8']);
    assert_same(null, $plugin->resolveClientIp(), 'Mismatched Forwarded quote');

    request_from('10.0.0.1', ['HTTP_FORWARDED' => 'for=""']);
    assert_same(null, $plugin->resolveClientIp(), 'Empty quoted Forwarded value');
});

test_case('trusted proxy supports Forwarded IPv4 and quoted IPv6', function () {
    $plugin = plugin_with_config(['10.0.0.0/8', '2001:db8::/32']);

    request_from('10.0.0.1', ['HTTP_FORWARDED' => 'for=8.8.8.8:443']);
    assert_same('8.8.8.8', $plugin->resolveClientIp(), 'Forwarded IPv4 with port');

    request_from('2001:db8::1', ['HTTP_FORWARDED' => 'for="[2606:4700:4700::1111]:443"']);
    assert_same('2606:4700:4700::1111', $plugin->resolveClientIp(), 'Forwarded IPv6 with port');
});

test_case('Forwarded and X-Forwarded-For must agree', function () {
    $plugin = plugin_with_config(['10.0.0.0/8']);

    request_from('10.0.0.1', [
        'HTTP_FORWARDED' => 'for=8.8.8.8',
        'HTTP_X_FORWARDED_FOR' => '8.8.8.8',
    ]);
    assert_same('8.8.8.8', $plugin->resolveClientIp(), 'Matching forwarding headers');

    request_from('10.0.0.1', [
        'HTTP_FORWARDED' => 'for=8.8.8.8',
        'HTTP_X_FORWARDED_FOR' => '1.1.1.1',
    ]);
    assert_same(null, $plugin->resolveClientIp(), 'Conflicting forwarding headers');
});

test_case('private client policy applies to the rightmost untrusted address', function () {
    request_from('10.0.0.1', [
        'HTTP_X_FORWARDED_FOR' => '8.8.8.8, 192.168.1.5, 10.0.0.2',
    ]);

    assert_same(null, plugin_with_config(['10.0.0.0/8'], false)->resolveClientIp(), 'Private client rejected');
    assert_same('192.168.1.5', plugin_with_config(['10.0.0.0/8'], true)->resolveClientIp(), 'Private client accepted');
});

test_case('empty and invalid trusted proxy environment values are ignored', function () {
    putenv('DOVECOT_CLIENT_IP_TRUSTED_PROXIES=');
    $plugin = plugin_with_config(['10.0.0.0/8']);
    $plugin->loadEnvironmentConfig();

    request_from('8.8.8.8', ['HTTP_X_FORWARDED_FOR' => '46.148.158.142']);
    assert_same('8.8.8.8', $plugin->resolveClientIp(), 'Empty environment value');

    putenv('DOVECOT_CLIENT_IP_TRUSTED_PROXIES=garbage,not-an-ip/0');
    $plugin->loadEnvironmentConfig();
    assert_same('8.8.8.8', $plugin->resolveClientIp(), 'Invalid environment values');

    putenv('DOVECOT_CLIENT_IP_TRUSTED_PROXIES=10.0.0.0/8');
    $plugin->loadEnvironmentConfig();
    request_from('10.0.0.1', ['HTTP_X_FORWARDED_FOR' => '1.1.1.1']);
    assert_same('1.1.1.1', $plugin->resolveClientIp(), 'Valid environment value');

    putenv('DOVECOT_CLIENT_IP_TRUSTED_PROXIES');
});

test_case('storage hook preserves identifiers and uses preauth_ident', function () {
    request_from('46.148.158.142');
    $plugin = plugin_with_config();
    $result = $plugin->on_storage_connect([
        'preauth_ident' => ['name' => 'Roundcube'],
    ]);

    assert_same('Roundcube', $result['preauth_ident']['name'], 'Existing identifier');
    assert_same('46.148.158.142', $result['preauth_ident']['x-originating-ip'], 'Originating IP identifier');

    request_from(null);
    assert_same(null, $plugin->on_storage_connect([]), 'Unresolved client IP hook result');
});

$failed = 0;

foreach ($tests as $name => $callback) {
    try {
        $callback();
        fwrite(STDOUT, "PASS {$name}\n");
    } catch (Exception $exception) {
        ++$failed;
        fwrite(STDERR, "FAIL {$name}: {$exception->getMessage()}\n");
    }
}

restore_error_handler();

if ($failed > 0) {
    exit(1);
}

fwrite(STDOUT, 'PASS all ' . count($tests) . " tests\n");
