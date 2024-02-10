<?php
namespace Pangea\Services;
use \Pangea\PangeaInterface;
/**
 * Remove sensitive information from free-from text and structured data 
 *
 * @link https://pangea.cloud/ 
 * @author Manomite Limited <manomitehq@gmail.com>
 * @version 1.0.0
 */

class REDACT implements PangeaInterface {
    protected $travel;
    protected $version;
    protected $url;

    public function setParentProperties(\Pangea\Pangea $parent, $endpoint){
        $this->travel = $parent;
        $this->version = $parent->version;
        $this->url = $endpoint;
    }

    //Redact sensitive information from provided text.
    public function text_redact(string $text, string $configID = "", array $rules = array(), array $rulesets = array(), bool $return_result = false, bool $debug = true){

        $response = $this->travel->post($this->url.'/'.$this->version.'/redact', [
            'text' => $text,
            'config_id' => $configID,
            'rules' => $rules,
            'rulesets' => $rulesets,
            'return_result' => $return_result,
            'debug' => $debug,
        ]);
        return $response;
    }

    //Redact sensitive information from structured data (e.g., JSON).
    public function complex_redact($data, array | string $jsonp, string $configID = "", array $rules = array(), array $rulesets = array(), bool $return_result = false, bool $debug = true){

        $response = $this->travel->post($this->url.'/'.$this->version.'/redact_structured', [
            'data' => $data,
            'jsonp' => $jsonp,
            'config_id' => $configID,
            'rules' => $rules,
            'rulesets' => $rulesets,
            'return_result' => $return_result,
            'format' => 'json',
            'debug' => $debug,
        ]);
        return $response;
    }
}