<?php
namespace Pangea;
/**
 * Pangea PHP SDK Implementations
 *
 * @link https://pangea.cloud/ 
 * @author Manomite Limited <manomitehq@gmail.com>
 * @version 1.0.0
 */
use \Curl\Curl;

class Pangea {
    public $transport;

    public $version = 'v1';
    protected $services = [];
    protected $token;
    protected $region;
    protected $csp;

    public function __construct($token, $csp, $region){
		
        $this->transport = new Curl();
        $this->transport->setHeader('Authorization', "Bearer {$token}");
        $this->transport->setHeader('Content-Type', 'application/json');

        $this->token = $token;
        $this->region = $region;
        $this->csp = $csp;
    }

    public function available_service(){
        return [
            'vault',
            'ip-intel',
            'domain-intel',
            'url-intel',
            'user-intel',
            'file-intel',
            'file-scan',
            'audit',
            'embargo',
            'redact'
        ];
    }

    public function registerService(...$services){
        foreach($services as $service){
            if (is_array($service)){
                foreach($service as $ser){
                    $this->registerService($ser);
                }
                return null;
            }
            $available_services = $this->available_service();
            if (!in_array(strtolower($service), $available_services)) {
                throw new \Exception('Invalid service. Please choose from the allowed service types ' . implode(', ', $available_services));
            }
            $endpoint = strtolower("https://{$service}.{$this->csp}.{$this->region}.pangea.cloud");
            $linked = str_replace('-', '', strtoupper($service));
            $class = "Pangea\\Services\\{$linked}";
            $service = new $class;
            if ($service instanceof \Pangea\PangeaInterface){
                $service->setParentProperties($this, $endpoint);
                $this->services[] = $service;
            }
            
        }
    }
    
    public function post($path, array $data){
        try {
            print_r($path);
            return $this->response($this->transport->post($path, json_encode($data)));
        } catch(\Exception $e) {
            return $this->error($e->getMessage());
        }
    }

    public function get($path, array $data){
        try {
            return $this->response($this->transport->get($path, $data));
        } catch(\Exception $e) {
            return $this->error($e->getMessage());
        }
    }

    private function error($message){
        throw new \Exception($message);
    }

    private function response($response){
        return json_decode(json_encode($response), true);
    }

    public function __call($methodName, $args){
        foreach($this->services as $service){
            if(method_exists($service, $methodName)){
                $reflection = new \ReflectionMethod($service, $methodName);
                if($reflection->isPublic()){
                    return $reflection->invokeArgs($service, $args);
                }
                throw new \Exception("Method {$methodName} cannot be publicly accessed.");
            }
        }
    }
}