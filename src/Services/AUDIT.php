<?php
namespace Pangea\Services;
use \Pangea\PangeaInterface;
/**
 * A managed audit log store that offers transparent, unalterable, and cryptographically verified transaction logs
 *
 * @link https://pangea.cloud/ 
 * @author Manomite Limited <manomitehq@gmail.com>
 * @version 1.0.0
 */

class   AUDIT implements PangeaInterface {

    protected $travel;

    protected $version;
    
    protected $url;

    public function setParentProperties(\Pangea\Pangea $parent, $endpoint){
        $this->travel = $parent;
        $this->version = 'v2';
        $this->url = $endpoint;
    }

   
}