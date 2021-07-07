<?php
/**
 * TOTP
 * A simple TOTP (RFC 6238) class using the SHA1 default
 *
 * @author      Robin Leffmann <djinn at stolendata dot net>
 * @author      Łukasz Jurczyk <zabszk at protonmail dot ch>
 * @copyright   2014 Robin Leffmann
 * @link        https://github.com/stolendata/totp
 * @copyright   2017 Łukasz Jurczyk
 * @link        https://github.com/zabszk/totp
 * @license     Creative Commons BY-NC-SA 4.0
 * @link        https://creativecommons.org/licenses/by-nc-sa/4.0
 *
 * @version     $Id$
 * @package     TOTP
*/

require_once 'lib/random.php';

class TOTP
{
    private static $base32Map = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * Base32 Decode
     *
     * @param   string  $in
     * @return  string
    */
    private static function base32Decode( $in )
    {
        $l = strlen( $in );
        $n = $bs = 0;

        for( $i = 0; $i < $l; $i++ )
        {
            $n <<= 5;
            $n += stripos( self::$base32Map, $in[$i] );
            $bs = ( $bs + 5 ) % 8;
            @$out .= $bs < 5 ? chr( ($n & (255 << $bs)) >> $bs ) : null;
        }

        return $out;
    }

    /**
     * Generate an OTP
     *
     * @param   string  $secret
     * @param   int     $digits
     * @param   int     $period
     * @param   int     $offset
     * @return  array
    */
    public static function getOTP( $secret, $digits = 6, $period = 30, $offset = 0 )
    {
        if( strlen($secret) < 16 || strlen($secret) % 8 != 0 )
            return [ 'err'=>'length of secret must be a multiple of 8, and at least 16 characters' ];
        if( preg_match('/[^a-z2-7]/i', $secret) === 1 )
            return [ 'err'=>'secret contains non-base32 characters' ];
        $digits = intval( $digits );
        if( $digits < 6 || $digits > 8 )
            return [ 'err'=>'digits must be 6, 7 or 8' ];

        $seed = self::base32Decode( $secret );
        $time = str_pad( pack('N', intval($offset + time() / $period)), 8, "\x00", STR_PAD_LEFT );
        $hash = hash_hmac( 'sha1', $time, $seed, false );
        $otp = ( hexdec(substr($hash, hexdec($hash[39]) * 2, 8)) & 0x7fffffff ) % pow( 10, $digits );

        return [ 'otp'=>sprintf("%'0{$digits}u", $otp) ];
    }

    /**
     * Generate a secret
     *
     * @param   int  $length
     * @return  array
    */
    public static function genSecret( $length = 24 )
    {
        if( $length < 16 || $length % 8 !== 0 )
            return [ 'err'=>'length must be a multiple of 8, and at least 16' ];

        while( $length-- )
        {
            try {
                @$secret .= self::$base32Map[random_int(0, 31)];
            } catch (TypeError $e) {
                die("An error has occurred");
            } catch (Error $e) {
                die("An error has occurred");
            } catch (Exception $e) {
                die("Could not generate a secure random int. Is our OS secure?");
            }
        }

        return [ 'secret'=>$secret ];
    }

    /**
     * Generate an OTP URI
     *
     * @param   string  $account
     * @param   string  $secret
     * @param   boolean $digits
     * @param   int     $period
     * @param   string  $issuer
     * @return  array
    */
    public static function genURI( $account, $secret, $digits = null, $period = null, $issuer = null )
    {
        if( empty($account) || empty($secret) )
            return [ 'err'=>'you must provide at least an account and a secret' ];
        if( mb_strpos($account . $issuer, ':') !== false )
            return [ 'err'=>'neither account nor issuer can contain a colon (:) character' ];

        $account = rawurlencode( $account );
        $issuer = rawurlencode( $issuer );
        $label = empty( $issuer ) ? $account : "$issuer:$account";

        return [ 'uri'=>'otpauth://totp/' . $label . "?secret=$secret" .
                        (is_null($digits) ? '' : "&digits=$digits") .
                        (is_null($period) ? '' : "&period=$period") .
                        (empty($issuer) ? '' : "&issuer=$issuer") ];
    }
}
