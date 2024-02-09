<?php
namespace Pangea\Services;
use \Pangea\PangeaInterface;
/**
 * Retrieve a reputation score for a URL from a provider, including an optional detailed report
 *
 * @link https://pangea.cloud/ 
 * @author Manomite Limited <manomitehq@gmail.com>
 * @version 1.0.0
 */

class URLINTEL implements PangeaInterface {

    protected $travel;

    protected $version;
    
    protected $url;

    public function setParentProperties(\Pangea\Pangea $parent, $endpoint){
        $this->travel = $parent;
        $this->version = 'v2';
        $this->url = $endpoint;
    }

    //Retrieve a reputation score for a URL from a provider, including an optional detailed report
    public function check_url(array $url){
        $response = $this->travel->post($this->url.'/'.$this->version.'/reputation', [
            'urls' => $url,
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }
}