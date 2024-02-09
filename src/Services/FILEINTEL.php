<?php
namespace Pangea\Services;
use \Pangea\PangeaInterface;
/**
 * Retrieve a reputation score for a set of file hashes from a provider, including an optional detailed report
 *
 * @link https://pangea.cloud/ 
 * @author Manomite Limited <manomitehq@gmail.com>
 * @version 1.0.0
 */

class FILEINTEL implements PangeaInterface {

    protected $travel;

    protected $version;
    
    protected $url;

    public function setParentProperties(\Pangea\Pangea $parent, $endpoint){
        $this->travel = $parent;
        $this->version = 'v2';
        $this->url = $endpoint;
    }

    /**
     * Retrieve a reputation score for a file hash from a provider, including an optional detailed report.
     *
     * @param string $hash_type (sha25, md5, sha1)
     * @param string $provider
     * @param string $content
     */
    public function file_intel(string $content ){
        $providers = ["reversinglabs", "crowdstrike"];
        $hash_types = ["sha256", "sha1", "md5"];
        $store = array();
        foreach ($providers as $provider) {
            foreach ($hash_types as $hash_type) {
                $hash = hash($hash_type, $content);
                $response = $this->travel->post($this->url.'/'.$this->version.'/reputation', [
                    'hash_type' => $hash_type,
                    'hash' => $hash,
                    'provider' => $provider,
                    'raw' => true,
                    'verbose' => true
                ]);
                if (is_array($response) and !empty($response)) {
                    if (isset($response['status'])) {
                        if (strtolower($response['status']) === 'success') {
                            $verdict = strtolower($response['result']['data']['verdict']);
                            if($verdict !== 'unknown'){
                                //File is dangerous. Be careful with this type of file
                                return array('provider' => $provider, 'hash_type' => $hash_type, 'report' => $response);
                            }
                        }
                        //Save informations for rechecking later. Use async_file_call() to recheck
                        if(strtolower($response['status']) === 'accepted'){
                            $payload = array(
                                'request_id' => $response['request_id'],
                                'status' => 'accepted'
                            );
                            $store[] = array('provider' => $provider, 'hash_type' => $hash_type, 'report' => $payload, 'description' => 'use async_file_call($request_id) with the request id to check for file scan update later.');
                        }
                    }
                }
            }
        }
        if(!empty($store)){
            return $store;
        }
        return 'not dangerous';
    }

    /**
     * Asynchronous call
     *
     * @param string $request_id
     */
    public function async_file_call(string $request_id){
        $response = $this->travel->get($this->url.'/request/'.$request_id, []);
        return $response;
    }
   
}