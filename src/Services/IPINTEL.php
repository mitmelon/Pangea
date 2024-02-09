<?php
namespace Pangea\Services;
use \Pangea\PangeaInterface;
/**
 * Retrieve a reputation score for an IP address from a provider, including an optional detailed report. When requesting reputation for multiple IP addresses, the response will be asynchronous
 *
 * @link https://pangea.cloud/ 
 * @author Manomite Limited <manomitehq@gmail.com>
 * @version 1.0.0
 */

class IPINTEL implements PangeaInterface {

    protected $travel;

    protected $version;

    protected $url;

    public function setParentProperties(\Pangea\Pangea $parent, $endpoint){
        $this->travel = $parent;
        $this->version = 'v2';
        $this->url = $endpoint;
    }

    public function reputation(array $ip){
        $response = $this->travel->post($this->url.'/'.$this->version.'/reputation', [
            'ips' => $ip,
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }

    //Retrieve the domain name associated with an IP address.
    public function domain(array $ip){
        $response = $this->travel->post($this->url.'/'.$this->version.'/domain', [
            'ips' => $ip,
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }

    public function proxy(array $ip){
        $response = $this->travel->post($this->url.'/'.$this->version.'/proxy', [
            'ips' => $ip,
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }

    public function vpn(array $ip){
        $response = $this->travel->post($this->url.'/'.$this->version.'/vpn', [
            'ips' => $ip,
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }

    public function geolocate(array $ip){
        $response = $this->travel->post($this->url.'/'.$this->version.'/geolocate', [
            'ips' => $ip,
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }
   
}