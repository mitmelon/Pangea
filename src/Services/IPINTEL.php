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

    public function ip_reputation(array $ip){
        $response = $this->travel->post($this->url.'/'.$this->version.'/reputation', [
            'ips' => $ip,
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }

    public function domain(array $ip){
        $response = $this->travel->post($this->url.'/'.$this->version.'/domain', [
            'ips' => $ip,
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }



   
}