<?php
namespace Pangea\Services;
use \Pangea\PangeaInterface;
/**
 * Determine if an email address, username, phone number, or IP address was exposed in a security breach
 *
 * @link https://pangea.cloud/ 
 * @author Manomite Limited <manomitehq@gmail.com>
 * @version 1.0.0
 */

class USERINTEL implements PangeaInterface {

    protected $travel;

    protected $version;
    
    protected $url;

    public function setParentProperties(\Pangea\Pangea $parent, $endpoint){
        $this->travel = $parent;
        $this->version = 'v2';
        $this->url = $endpoint;
    }

    //Retrieve reputation for a domain from a provider, including an optional detailed report
    public function user_breached(array $ip, string $start_date = '5000d', string $end_date = '0d', string $provider = 'spycloud'){
        $response = $this->travel->post($this->url.'/'.$this->version.'/user/breached', [
            'ips' => $ip,
            'start' => $start_date,
            'end' => $end_date,
            'provider' => $provider,
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }

    //Determine if a password has been exposed in a security breach using a 5 character prefix of the password hash. 
    public function password_breached(string $hash_type, string | array $hash_prefixes = '', string $provider = 'spycloud'){
        $response = $this->travel->post($this->url.'/'.$this->version.'/password/breached', [
            'hash_type' => $hash_type,
            'hash_prefixes' => $hash_prefixes,
            'provider' => $provider,
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }
}