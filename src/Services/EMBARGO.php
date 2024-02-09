<?php
namespace Pangea\Services;
use \Pangea\PangeaInterface;
/**
 * Determine if there is a trade embargo against the country of origin for an IP address
 *
 * @link https://pangea.cloud/ 
 * @author Manomite Limited <manomitehq@gmail.com>
 * @version 1.0.0
 */

class EMBARGO implements PangeaInterface {

    protected $travel;

    protected $version;
    
    protected $url;

    public function setParentProperties(\Pangea\Pangea $parent, $endpoint){
        $this->travel = $parent;
        $this->version = $parent->version;
        $this->url = $endpoint;
    }

    //Check IPs against known sanction and trade embargo lists.
    public function check_ip(string $ip){
        $response = $this->travel->post($this->url.'/'.$this->version.'/ip/check', [
            'ip' => $ip
        ]);
        return $response;
    }

    //Check country codes against known sanction and trade embargo lists.
    public function check_iso(string $iso_code){
        $response = $this->travel->post($this->url.'/'.$this->version.'/iso/check', [
            'iso_code' => $iso_code
        ]);
        return $response;
    }
}