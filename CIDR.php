<?php
/**
 * CIDR class helps validate an ip address against a CIDR ip range.
 *
 * This class compares IPv4 and IPv6 addresses with exact addresses or CIDR
 * networks.
 *
 * @package     CIDR
 * @version     1.0
 * @author      Frank Forte
 * @copyright   Copyright (c) 2015 Frank Forte
 * @license     BSD-3 License https://opensource.org/licenses/BSD-3-Clause
 */

 namespace dovecot_client_ip;
class CIDR{

   /**
	* compare an IPv4 or IPv6 address with a CIDR address or range
	*
	* @param  string  $ip a valid IPv4 or IPv6 address
	* @param  string  $cidr a valid IPv4 or IPv6 address[/mask]
	* @return boolean	whether $address is within the ip range made up  of the subnet and mask
	*/
    public static function match($ip, $cidr){
		if (!is_string($ip)) {
			return false;
		}

		$ip = trim($ip);
		if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
			return false;
		}

		$packedIp = inet_pton($ip);
		$network = self::parseNetwork($cidr);

		if ($packedIp === false || $network === false) {
			return false;
		}

		$packedSubnet = $network[0];
		$mask = $network[1];

		if (strlen($packedIp) !== strlen($packedSubnet)) {
			return false;
		}

		$wholeBytes = (int) floor($mask / 8);
		$remainingBits = $mask % 8;

		if ($wholeBytes > 0 && substr($packedIp, 0, $wholeBytes) !== substr($packedSubnet, 0, $wholeBytes)) {
			return false;
		}

		if ($remainingBits === 0) {
			return true;
		}

		$maskByte = (0xFF << (8 - $remainingBits)) & 0xFF;

		return (ord($packedIp[$wholeBytes]) & $maskByte) === (ord($packedSubnet[$wholeBytes]) & $maskByte);
    }

    /**
	* Check whether an exact IP or CIDR network is valid.
	*
	* @param mixed $network
	* @return boolean
	*/
    public static function isValidNetwork($network)
    {
		return self::parseNetwork($network) !== false;
    }

    /**
	* @param mixed $network
	* @return array|false Packed subnet and mask size, or false when invalid.
	*/
    private static function parseNetwork($network)
    {
		if (!is_string($network)) {
			return false;
		}

		$network = trim($network);
		if ($network === '' || substr_count($network, '/') > 1) {
			return false;
		}

		$parts = explode('/', $network, 2);
		$subnet = trim($parts[0]);
		if (filter_var($subnet, FILTER_VALIDATE_IP) === false) {
			return false;
		}

		$packedSubnet = inet_pton($subnet);

		if ($packedSubnet === false) {
			return false;
		}

		$maxMask = strlen($packedSubnet) * 8;
		if (count($parts) === 1) {
			return array($packedSubnet, $maxMask);
		}

		$mask = trim($parts[1]);
		if ($mask === '' || !ctype_digit($mask)) {
			return false;
		}

		$mask = (int) $mask;
		if ($mask < 0 || $mask > $maxMask) {
			return false;
		}

		return array($packedSubnet, $mask);
    }



   /**
	* Check IPv6 address is within an IP range
	*
	* @param  string  $address a valid IPv6 address
	* @param  string  $subnet a valid IPv6 subnet
	* @param  string  $mask a valid IPv6 subnet mask
	* @return boolean	whether $address is within the ip range made up  of the subnet and mask
	*/
    private static function IPv6Match($ip, $subnet, $mask)
    {
        $subnet = inet_pton($subnet);
        $ip = inet_pton($ip);

		// thanks to MW on http://stackoverflow.com/questions/7951061/matching-ipv6-address-to-a-cidr-subnet
		$binMask = str_repeat("f", $mask / 4);
        switch ($mask % 4) {
            case 0:
                break;
            case 1:
                $binMask .= "8";
                break;
            case 2:
                $binMask .= "c";
                break;
            case 3:
                $binMask .= "e";
                break;
        }
        $binMask = str_pad($binMask, 32, '0');
        $binMask = pack("H*", $binMask);


        return ($ip & $binMask) == $subnet;
    }

   /**
	* Check IPv4 address is within an IP range
	*
	* @param  string  $address a valid IPv4 address
	* @param  string  $subnet a valid IPv4 subnet
	* @param  string  $mask a valid IPv4 subnet mask
	* @return boolean	whether $address is within the ip rage made up  of the subnet and mask
	*/
	 private static function IPv4Match($address, $subnet, $mask)
    {
		// credit goes to Sam on http://stackoverflow.com/questions/594112/matching-an-ip-to-a-cidr-mask-in-php5
        if ((ip2long($address) & ~((1 << (32 - $mask)) - 1)) == ip2long($subnet)) {
            return true;
        }

        return false;
    }

	/**
	* Compress an IPv6 Address
	*
	* @param  string  $ip a valid IPv6 address or CIDR
	* @return string  IPv6 ip address or CIDR in short form notation
	*/
	public static function IPv6_compress($ip)
	{
		$bits = explode('/',$ip); // in case this is a CIDR range
		
		// want to expand and re-compress in case we have "::" in different spots.
		$bits[0] = self::IPv6_expand($bits[0]);

		$bits[0] = inet_ntop(inet_pton($bits[0]));
		return strtolower(implode('/',$bits));
	}

	/**
	* Expand an IPv6 Address
	*
	* @param  string  $ip a valid IPv6 address
	* @return string  IPv6 ip address in long form notation
	*/
	public static function IPv6_expand($ip){
		
		$bits = explode('/',$ip); // in case this is a CIDR range
		
		// add missing components
		if (strpos($bits[0], '::') !== false) {
			$part = explode('::', $bits[0]);
			$part[0] = explode(':', $part[0]);
			$part[1] = explode(':', $part[1]);
			$missing = array();
			for ($i = 0; $i < (8 - (count($part[0]) + count($part[1]))); $i++)
				array_push($missing, '0000');
			$missing = array_merge($part[0], $missing);
			$part = array_merge($missing, $part[1]);
		} else {
			$part = explode(":", $bits[0]);
		}
		
		// Pad components to 4 characters
		foreach ($part as &$p) {
			while (strlen($p) < 4) $p = '0' . $p;
		}
		unset($p);

		$bits[0] = implode(':', $part);

		// if it is the incorrect length, something went wrong.
		if (strlen($bits[0]) != 39) {
			return false;
		}
		return strtolower(implode('/',$bits));
	}
}
?>
