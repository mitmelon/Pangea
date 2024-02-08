<?php
namespace Compress\SDK;
/**
 * Pangea PHP SDK Implementations
 *
 * @link https://pangea.cloud/ 
 * @author Manomite Limited <manomitehq@gmail.com>
 * @version 1.0.0
 */
use \Curl\Curl;

class Pangea {
    protected $transport;
    protected $endpoint;

    public $version = 'v1';

    public function __construct($token, $service, $csp, $region){
		
        $available_services = $this->available_service();
        if (!in_array(strtolower($service), $available_services)) {
            throw new \Exception('Invalid service. Please choose from the allowed service types ' . implode(', ', $available_services));
        }

        $this->endpoint = strtolower("https://{$service}.{$csp}.{$region}.pangea.cloud");
        $this->transport = new Curl();
        $this->transport->setHeader('Authorization', "Bearer {$token}");
        $this->transport->setHeader('Content-Type', 'application/json');
    }

    protected function available_service(){
        return $available_services = [
            'vault',
        ];
    }

    protected function post($path, array $data){
        try {
            return $this->response($this->transport->post($this->endpoint.$path, json_encode($data)));
        } catch(\Exception $e) {
            return $this->error($e->getMessage());
        }
    }

    protected function get($path, array $data){
        try {
            return $this->response($this->transport->get($this->endpoint.$path, $data));
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
}