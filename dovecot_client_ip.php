<?php
/*
 * RoundCube Dovecot Client IP Plugin
 *
 * Copyright (C) 2021, Michael Maier
 * Copyright (C) 2024, foorschtbar
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

require_once(__DIR__ . '/CIDR.php');

/**
 * Dovecot Client IP
 *
 * Provides the HTTP client IP during IMAP connect to Dovecot in the form of
 * an IMAP identifier for proper authentication penalty processing.
 *
 * Requires the webmail server to be added to login_trusted_networks in the
 * Dovecot configuration.
 *
 * Takes reverse proxy headers into account to determine the actual client IP.
 *
 * @author Michael Maier
 * @author foorschtbar
 * @url https://github.com/foorschtbar/dovecot_client_ip
 * @url https://gitlab.com/takerukoushirou/roundcube-dovecot_client_ip
 * @url https://doc.dovecot.org/settings/core/#login-trusted-networks
 * @url https://doc.dovecot.org/configuration_manual/authentication/auth_penalty/
 * @url https://doc.dovecot.org/configuration_manual/proxy_settings/
 */
class dovecot_client_ip extends rcube_plugin
{

    /**
     * @url https://github.com/roundcube/roundcubemail/wiki/Plugin-Hooks#task-mail
     * @url https://github.com/roundcube/roundcubemail/wiki/Plugin-Hooks#task-login
     */
    // Both mail and login tasks invoke storage_connect callbacks.
    public $task = 'mail|login';

    const TrustedProxiesConfigKey = 'dovecot_client_ip_trusted_proxies';
    const ProxyAllowPrivateClientIpConfigKey = 'dovecot_client_ip_proxy_allow_private_client_ip';

    private $rc;

    public
    function init()
    {
        $this->rc = rcmail::get_instance();

        $this->load_config();

        // Override config with environment variables if they exist
        $this->load_env_config();

        $this->add_hook('storage_connect', [$this, 'on_storage_connect']);
    }

    /**
     * Load configuration from environment variables if they exist
     * Environment variables take precedence over config file
     */
    protected function load_env_config()
    {
        // Check for trusted proxies environment variable
        $env_trusted_proxies = getenv('DOVECOT_CLIENT_IP_TRUSTED_PROXIES');
        if ($env_trusted_proxies !== false) {
            $trusted_proxies = [];

            foreach (explode(',', $env_trusted_proxies) as $trusted_proxy) {
                $trusted_proxy = trim($trusted_proxy);

                if (dovecot_client_ip\CIDR::isValidNetwork($trusted_proxy)) {
                    $trusted_proxies[$trusted_proxy] = $trusted_proxy;
                }
            }

            $this->rc->config->set(static::TrustedProxiesConfigKey, array_values($trusted_proxies));
        }

        // Check for allow private client IP environment variable
        $env_allow_private = getenv('DOVECOT_CLIENT_IP_PROXY_ALLOW_PRIVATE_CLIENT_IP');
        if ($env_allow_private !== false) {
            // Convert to boolean (any non-empty value except "0", "false", "no" is considered true)
            $allow_private = !in_array(strtolower($env_allow_private), ['0', 'false', 'no', ''], true);
            $this->rc->config->set(static::ProxyAllowPrivateClientIpConfigKey, $allow_private);
        }
    }

    /**
     * Resolves the client IP by taking proxy headers into account.
     *
     * If REMOTE_ADDR matches one of the configured trusted proxies, the
     * Forwarded and X-Forwarded-For chains are processed from right to left.
     *
     * By default, private range IP addresses are skipped unless explicitly
     * enabled in the configuration.
     *
     * @return string|null Client IP address, or null when it cannot be trusted.
     */
    protected
    function get_client_ip()
    {
        $trusted_proxies = $this->get_trusted_proxies();
        $allow_private_client_ip = $this->rc->config->get(static::ProxyAllowPrivateClientIpConfigKey);
        $remoteAddress = $this->normalize_ip(isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : null);

        if ($remoteAddress === null) {
            return null;
        }

        if (!$this->ip_matches_any_network($remoteAddress, $trusted_proxies)) {
            return $remoteAddress;
        }

        return $this->get_forwarded_client_ip($trusted_proxies, (bool) $allow_private_client_ip);
    }

    /**
     * @return array Valid, unique trusted proxy addresses and CIDR networks.
     */
    protected function get_trusted_proxies()
    {
        $configured_proxies = $this->rc->config->get(static::TrustedProxiesConfigKey);
        $trusted_proxies = [];

        if (!is_array($configured_proxies)) {
            return $trusted_proxies;
        }

        foreach ($configured_proxies as $trusted_proxy) {
            if (!dovecot_client_ip\CIDR::isValidNetwork($trusted_proxy)) {
                continue;
            }

            $trusted_proxy = trim($trusted_proxy);
            $trusted_proxies[$trusted_proxy] = $trusted_proxy;
        }

        return array_values($trusted_proxies);
    }

    /**
     * @param string $ip
     * @param array $networks
     * @return boolean
     */
    protected function ip_matches_any_network($ip, $networks)
    {
        foreach ($networks as $network) {
            if (dovecot_client_ip\CIDR::match($ip, $network)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Resolve supported forwarding headers and reject incomplete or
     * contradictory chains.
     *
     * @param array $trusted_proxies
     * @param boolean $allow_private_client_ip
     * @return string|null
     */
    protected function get_forwarded_client_ip($trusted_proxies, $allow_private_client_ip)
    {
        $forwarded_header = $this->get_server_header('HTTP_FORWARDED');
        $x_forwarded_for_header = $this->get_server_header('HTTP_X_FORWARDED_FOR');

        if ($forwarded_header === null && $x_forwarded_for_header === null) {
            return null;
        }

        $forwarded_ip = null;
        if ($forwarded_header !== null) {
            $forwarded_ips = $this->parse_forwarded_header($forwarded_header);
            if ($forwarded_ips === false) {
                return null;
            }

            $forwarded_ip = $this->resolve_trusted_chain(
                $forwarded_ips,
                $trusted_proxies,
                $allow_private_client_ip
            );
            if ($forwarded_ip === null) {
                return null;
            }
        }

        $x_forwarded_for_ip = null;
        if ($x_forwarded_for_header !== null) {
            $x_forwarded_for_ips = $this->parse_x_forwarded_for_header($x_forwarded_for_header);
            if ($x_forwarded_for_ips === false) {
                return null;
            }

            $x_forwarded_for_ip = $this->resolve_trusted_chain(
                $x_forwarded_for_ips,
                $trusted_proxies,
                $allow_private_client_ip
            );
            if ($x_forwarded_for_ip === null) {
                return null;
            }
        }

        if ($forwarded_ip !== null && $x_forwarded_for_ip !== null) {
            return $this->ips_equal($forwarded_ip, $x_forwarded_for_ip) ? $forwarded_ip : null;
        }

        return $forwarded_ip !== null ? $forwarded_ip : $x_forwarded_for_ip;
    }

    /**
     * @param string $header
     * @return array|false
     */
    protected function parse_x_forwarded_for_header($header)
    {
        $ips = [];

        foreach (explode(',', $header) as $token) {
            $ip = $this->normalize_ip($token);
            if ($ip === null) {
                return false;
            }

            $ips[] = $ip;
        }

        return $ips === [] ? false : $ips;
    }

    /**
     * @param string $header
     * @return array|false
     */
    protected function parse_forwarded_header($header)
    {
        $ips = [];

        foreach (explode(',', $header) as $element) {
            $found_for = false;
            $forwarded_ip = null;

            foreach (explode(';', $element) as $parameter) {
                $pair = explode('=', $parameter, 2);
                if (count($pair) !== 2 || strtolower(trim($pair[0])) !== 'for') {
                    continue;
                }

                if ($found_for) {
                    return false;
                }

                $found_for = true;
                $forwarded_ip = $this->parse_forwarded_for_value(trim($pair[1]));
                if ($forwarded_ip === null) {
                    return false;
                }
            }

            if (!$found_for || $forwarded_ip === null) {
                return false;
            }

            $ips[] = $forwarded_ip;
        }

        return $ips === [] ? false : $ips;
    }

    /**
     * @param string $value
     * @return string|null
     */
    protected function parse_forwarded_for_value($value)
    {
        if ($value === '') {
            return null;
        }

        if ($value[0] === '"') {
            if (strlen($value) < 2 || substr($value, -1) !== '"' || strpos($value, '\\') !== false) {
                return null;
            }

            $value = substr($value, 1, -1);
        } elseif (strpos($value, '"') !== false) {
            return null;
        }

        if ($value === '') {
            return null;
        }

        if (strtolower($value) === 'unknown' || $value[0] === '_') {
            return null;
        }

        if (preg_match('/^\[([0-9a-f:.]+)\](?::[0-9]+)?$/i', $value, $matches) === 1) {
            $value = $matches[1];
        } elseif (preg_match('/^(\d{1,3}(?:\.\d{1,3}){3})(?::[0-9]+)$/', $value, $matches) === 1) {
            $value = $matches[1];
        }

        return $this->normalize_ip($value);
    }

    /**
     * @param array $ips
     * @param array $trusted_proxies
     * @param boolean $allow_private_client_ip
     * @return string|null
     */
    protected function resolve_trusted_chain($ips, $trusted_proxies, $allow_private_client_ip)
    {
        for ($index = count($ips) - 1; $index >= 0; --$index) {
            $ip = $ips[$index];

            if ($this->ip_matches_any_network($ip, $trusted_proxies)) {
                continue;
            }

            $filter_flags = FILTER_FLAG_NO_RES_RANGE;
            if (!$allow_private_client_ip) {
                $filter_flags |= FILTER_FLAG_NO_PRIV_RANGE;
            }

            return filter_var($ip, FILTER_VALIDATE_IP, $filter_flags) !== false ? $ip : null;
        }

        return null;
    }

    /**
     * @param string $server_key
     * @return string|null
     */
    protected function get_server_header($server_key)
    {
        if (!isset($_SERVER[$server_key]) || !is_string($_SERVER[$server_key])) {
            return null;
        }

        $value = trim($_SERVER[$server_key]);

        return $value === '' ? null : $value;
    }

    /**
     * @param mixed $value
     * @return string|null
     */
    protected function normalize_ip($value)
    {
        if (!is_string($value)) {
            return null;
        }

        $value = trim($value);
        if (filter_var($value, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        $packed = inet_pton($value);
        $normalized = inet_ntop($packed);

        return $normalized === false ? null : strtolower($normalized);
    }

    /**
     * @param string $left
     * @param string $right
     * @return boolean
     */
    protected function ips_equal($left, $right)
    {
        $packed_left = inet_pton($left);
        $packed_right = inet_pton($right);

        return $packed_left !== false && $packed_right !== false && $packed_left === $packed_right;
    }

    /**
     * Adds the X-Originating-IP with the actual IP of the HTTP client to the
     * IMAP identifier sent before authentication.
     *
     * @param array $args
     *
     * @return array
     */
    public
    function on_storage_connect($args)
    {
        $ident = [];
        $ident_key = 'ident';
        $client_ip = $this->get_client_ip();

        if ($client_ip === null) {
            // Failed to determine client IP, skip.
            return null;
        }

        if (version_compare(version_parse(RCMAIL_VERSION), version_parse('1.5'), '>=')) {
            // Starting with RoundCube 1.5, a new preauth_ident field was added
            // as the other identifiers will be only provided after authentication.
            // https://github.com/roundcube/roundcubemail/issues/7860
            // https://github.com/roundcube/roundcubemail/blob/master/program/lib/Roundcube/rcube_imap_generic.php#L913
            $ident_key = 'preauth_ident';
        }

        // RoundCube IMAP by default puts some server and version information
        // fields as the IMAP identifier. This options array is merged with
        // the documented hook arguments and should be retained.
        // https://github.com/roundcube/roundcubemail/blob/master/program/lib/Roundcube/rcube_imap.php#L118
        if (isset($args[$ident_key]) && is_array($args[$ident_key])) {
            $ident = $args[$ident_key];
        }

        // Add the actual IP of the client.
        // https://www.dovecot.org/list/dovecot/2013-July/091271.html
        // https://doc.dovecot.org/settings/core/#login-trusted-networks
        $ident['x-originating-ip'] = $client_ip;

        // Returned data is merged with arguments and provided back to the
        // IMAP connect method.
        return [$ident_key => $ident];
    }
}
