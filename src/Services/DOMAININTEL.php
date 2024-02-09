<?php
namespace Pangea\Services;
use \Pangea\PangeaInterface;
/**
 * Retrieve reputation for a domain from a provider, including an optional detailed report.
 *
 * @link https://pangea.cloud/ 
 * @author Manomite Limited <manomitehq@gmail.com>
 * @version 1.0.0
 */

class DOMAININTEL implements PangeaInterface {

    protected $travel;

    protected $version;
    
    protected $url;

    public function setParentProperties(\Pangea\Pangea $parent, $endpoint){
        $this->travel = $parent;
        $this->version = 'v2';
        $this->url = $endpoint;
    }

    //Retrieve reputation for a domain from a provider, including an optional detailed report
    public function domain_intel(array $ip){
        $response = $this->travel->post($this->url.'/'.$this->version.'/reputation', [
            'ips' => $ip,
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }

    //Retrieve who is for a domain from a provider, including an optional detailed report.
    public function whois(string $domain){
        $response = $this->travel->post($this->url.'/v1/whois', [
            'domain' => $domain,
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }
   
}