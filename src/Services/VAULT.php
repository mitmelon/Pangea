<?php
namespace Pangea\Services;
use \Pangea\PangeaInterface;
/**
 * Provides secure storage of secrets, cryptographic keys, and Pangea API Tokens tokens as Vault items. Easily generate, import, and manage secrets and keys to stay compliant and secure.
 *
 * @link https://pangea.cloud/ 
 * @author Manomite Limited <manomitehq@gmail.com>
 * @version 1.0.0
 */

class VAULT implements PangeaInterface {

    private $allowed_type = ["symmetric_key", "asymmetric_key"];
    private $allowed_purpose = ["encryption", "jwt"];
    private $allowed_state = ["active", "deactivated", "destroyed", "inherited", "suspended", "compromised"];
    private $asymmetric_algo = ["ED25519", "RSA-PKCS1V15-2048-SHA256", "ES256", "ES384", "ES512", "ES256K", "RSA-PSS-2048-SHA256", "RSA-PSS-3072-SHA256", "RSA-PSS-4096-SHA256", "RSA-PSS-4096-SHA512", "ED25519-DILITHIUM2", "ED448-DILITHIUM3", "SPHINCSPLUS-128-SHAKE256-SIMPLE", "SPHINCSPLUS-128-SHAKE256-ROBUST", "SPHINCSPLUS-128-SHA256-SIMPLE", "SPHINCSPLUS-128-SHA256-ROBUST", "SPHINCSPLUS-192-SHAKE256-SIMPLE", "SPHINCSPLUS-192-SHAKE256-ROBUST", "SPHINCSPLUS-192-SHA256-SIMPLE", "SPHINCSPLUS-192-SHA256-ROBUST", "SPHINCSPLUS-256-SHAKE256-SIMPLE", "SPHINCSPLUS-256-SHAKE256-ROBUST", "SPHINCSPLUS-256-SHA256-SIMPLE", "SPHINCSPLUS-256-SHA256-ROBUST", "RSA-OAEP-2048-SHA1", "RSA-OAEP-2048-SHA256", "RSA-OAEP-2048-SHA512", "RSA-OAEP-3072-SHA1", "RSA-OAEP-3072-SHA256", "RSA-OAEP-3072-SHA512", "RSA-OAEP-4096-SHA1", "RSA-OAEP-4096-SHA256", "RSA-OAEP-4096-SHA512", "ES256", "ES384", "ES512"];
    private $symmetric_algo_jwt = ["AES-CFB-128", "AES-CFB-256", "AES-GCM-256", "AES-CBC-128", "AES-CBC-256", "HS256", "HS384", "HS512"];
    private $symmetric_algo_encryption = ["AES-CFB-128", "AES-CFB-256", "AES-GCM-256", "AES-CBC-128", "AES-CBC-256"];
    protected $travel;
    protected $version;
    protected $url;

    public function setParentProperties(\Pangea\Pangea $parent, $endpoint){
        $this->travel = $parent;
        $this->version = $parent->version;
        $this->url = $endpoint;
    }

    public function generateKey(string $type, string $algorithm, string $purpose = "encryption", string $keyName = '', string $folderName = '', object $metadata = new \stdClass(), array $tags = array(), string $rotation_frequency = '10d', string $rotation_state = 'inherited', string $expiration = ''){
        if (!in_array(strtolower($type), $this->allowed_type)) {
            throw new \Exception('Invalid key type. Please choose from the allowed key types ' . implode(', ', $this->allowed_type));
        }

        if (!in_array(strtolower($purpose), $this->allowed_purpose)) {
            throw new \Exception('Invalid purpose type. Please choose from the allowed purpose types ' . implode(', ', $this->allowed_purpose));
        }

        $algo = str_replace('_key', '', $type).'_algo_'.$purpose;
        if (!in_array($algorithm, $this->$algo)) {
            throw new \Exception('Invalid algorithm. Please choose from the allowed types ' . implode(', ', $this->$algo));
        }

        if (!in_array(strtolower($rotation_state), $this->allowed_state)) {
            throw new \Exception('Invalid rotation state. Please choose from the allowed state types ' . implode(', ', $this->allowed_state));
        }
        $expire = array();
        if(!empty($expiration)){
            $expire = array('expiration' => $expiration);
        }

        $response = $this->travel->post($this->url.'/'.$this->version.'/key/generate', array_merge([
            'type' => $type,
            'algorithm' => $algorithm,
            'purpose' => $purpose,
            'name' => $keyName,
            'folder' => $folderName,
            'metadata' => $metadata,
            'tags' => $tags,
            'rotation_frequency' => $rotation_frequency,
            'rotation_state' => $rotation_state,
        ], $expire));
        return $response;
    }

    public function rotateKey($id, string $rotation_state = 'inherited'){
        if (!in_array(strtolower($rotation_state), $this->allowed_state)) {
            throw new \Exception('Invalid rotation state. Please choose from the allowed state types ' . implode(', ', $this->allowed_state));
        }
        $response = $this->travel->post($this->url.'/'.$this->version.'/key/rotate', [
            'id' => $id,
            'rotation_state' => $rotation_state
        ]);
        return $response;
    }

    public function encrypt($id, string $text, string $additional_data = ''){
        $response = $this->travel->post($this->url.'/'.$this->version.'/key/encrypt', [
            'id' => $id,
            'plain_text' => base64_encode($text),
            'additional_data' => $additional_data,
        ]);
        return $response;
    }

    public function decrypt($id, string $cipher, string $additional_data = ''){
        $response = $this->travel->post($this->url.'/'.$this->version.'/key/decrypt', [
            'id' => $id,
            'cipher_text' => $cipher,
            'additional_data' => $additional_data,
        ]);
        if($response['status'] === 'Success'){
            $response['result']['plain_text'] = base64_decode($response['result']['plain_text']);
            return $response;
        }
        return $response;
    }

    public function sign($id, string $message){
        $response = $this->travel->post($this->url.'/'.$this->version.'/key/sign', [
            'id' => $id,
            'message' => $message,
        ]);
        return $response;
    }

    public function verify($id, string $message, string $signature){
        $response = $this->travel->post($this->url.'/'.$this->version.'/key/verify', [
            'id' => $id,
            'message' => $message,
            'signature' => $signature,
        ]);
        return $response;
    }

    public function store(string $type, string $algorithm, string $public_key, $private_key, string $purpose = "encryption", string $keyName = '', string $folderName = '', object $metadata = new \stdClass(), array $tags = array(), string $rotation_frequency = '10d', string $rotation_state = 'inherited', string $expiration = ''){
       
        if (!in_array(strtolower($type), $this->allowed_type)) {
            throw new \Exception('Invalid key type. Please choose from the allowed key types ' . implode(', ', $this->allowed_type));
        }
        if (!in_array(strtolower($purpose), $this->allowed_purpose)) {
            throw new \Exception('Invalid purpose type. Please choose from the allowed purpose types ' . implode(', ', $this->allowed_purpose));
        }

        $algo = str_replace('_key', '', $type).'_algo_'.$purpose;
        if (!in_array($algorithm, $this->$algo)) {
            throw new \Exception('Invalid algorithm. Please choose from the allowed types ' . implode(', ', $this->$algo));
        }

        if (!in_array(strtolower($rotation_state), $this->allowed_state)) {
            throw new \Exception('Invalid rotation state. Please choose from the allowed state types ' . implode(', ', $this->allowed_state));
        }
        $expire = array();
        if(!empty($expiration)){
            $expire = array('expiration' => $expiration);
        }
        $response = $this->travel->post($this->url.'/'.$this->version.'/key/store', array_merge([
            'type' => $type,
            'algorithm' => $algorithm,
            'purpose' => $purpose,
            'public_key' => $public_key,
            'private_key' => $private_key,
            'name' => $keyName,
            'folder' => $folderName,
            'metadata' => $metadata,
            'tags' => $tags,
            'rotation_frequency' => $rotation_frequency,
            'rotation_state' => $rotation_state,
            'expiration' => $expiration,
        ], $expire));
        return $response;
    }

    public function createFolder($folderName, string $path, object $metadata = new \stdClass(), array $tags = array(), string $rotation_frequency = '10d', string $rotation_state = 'inherited', string $expiration = ''){
        $expire = array();
        if(!empty($expiration)){
            $expire = array('expiration' => $expiration);
        }
        $response = $this->travel->post($this->url.'/'.$this->version.'/folder/create', array_merge([
            'name' => $folderName,
            'folder' => $path,
            'metadata' => $metadata,
            'tags' => $tags,
            'rotation_frequency' => $rotation_frequency,
            'rotation_state' => $rotation_state,
            'expiration' => $expiration
        ], $expire));
        return $response;
    }

    public function signJWT($id, string $payload){
        $response = $this->travel->post($this->url.'/'.$this->version.'/key/sign/jwt', [
            'id' => $id,
            'payload' => $payload,
        ]);
        return $response;
    }

    public function verifyJWT($jws){
        $response = $this->travel->post($this->url.'/'.$this->version.'/key/verify/jwt', [
            'jws' => $jws,
        ]);
        return $response;
    }

    public function getJWT($id){
        $response = $this->travel->post($this->url.'/'.$this->version.'/key/get/jwt', [
            'id' => $id
        ]);
        return $response;
    }

    public function rotateSecret($id, $secret = ''){
        $response = $this->travel->post($this->url.'/'.$this->version.'/key/secret/rotate', [
            'id' => $id,
            'secret' => $secret,
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }

    public function storeSecret($type, $secret = '', string $name = '', string $folderPath = '', object $metadata = new \stdClass(), array $tags = array(), string $rotation_frequency = '10d', string $rotation_state = 'inherited', string $rotation_grace_period = '7d', string $expiration = ''){

        $allowed_type = ["secret", "pangea_token"];

        if (!in_array(strtolower($type), $allowed_type)) {
            throw new \Exception('Invalid allowed type. Please choose from the allowed types ' . implode(', ', $allowed_type));
        }

        if (!in_array(strtolower($rotation_state), $this->allowed_state)) {
            throw new \Exception('Invalid rotation state. Please choose from the allowed state types ' . implode(', ', $this->allowed_state));
        }

        $expire = array();
        if(!empty($expiration)){
            $expire = array('expiration' => $expiration);
        }

        $response = $this->travel->post($this->url.'/'.$this->version.'/key/secret/store', array_merge([
            'type' => $type,
            'secret' => $secret,
            'name' => $name,
            'folder' => $folderPath,
            'metadata' => $metadata,
            'tags' => $tags,
            'rotation_frequency' => $rotation_frequency,
            'rotation_state' => $rotation_state,
            'expiration' => $expiration
        ], $expire));
        return $response;
    }


    //Retrieve a secret, key or folder, and any associated information.
    public function getKey($id, $secret = ''){
        $response = $this->travel->post($this->url.'/'.$this->version.'/get', [
            'id' => $id,
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }

    public function listKey(array $filter, int $size = 20, string $order = 'asc', string $order_by = 'name', string $lastID = '', bool $include_secrets = false, array | string $include = ''){

        $order_type = ["asc", "desc"];
        $order_by_type = ["id", "type", "created_at", "algorithm", "purpose", "expiration", "last_rotated", "next_rotation", "name", "folder", "item_state"];

        if (!in_array(strtolower($order), $order_type)) {
            throw new \Exception('Invalid order type. Please choose from the allowed order types ' . implode(', ', $order_type));
        }
        if (!in_array(strtolower($order_by), $order_by_type)) {
            throw new \Exception('Invalid order by type. Please choose from the allowed order by types ' . implode(', ', $order_by_type));
        }

        $response = $this->travel->post($this->url.'/'.$this->version.'/list', [
            'filter' => $filter,
            'size' => $size,
            'order' => $order,
            'order_by' => $order_by,
            'last' => $lastID,
            'include_secrets' => $include_secrets,
            'include' => $include,
        ]);
        return $response;
    }

    //Update information associated with a secret, key or folder.
    public function updateSecret(string $id, string $name = '', string $folderPath = '', object $metadata = new \stdClass(), array $tags = array(), string $rotation_frequency = '10d', string $rotation_state = 'inherited', string $rotation_grace_period = '7d', string $expiration = '', string $item_state = 'enabled'){

        $allowed_item_type = ["enabled", "disabled"];

        if (!in_array(strtolower($item_state), $allowed_item_type)) {
            throw new \Exception('Invalid allowed type. Please choose from the allowed types ' . implode(', ', $allowed_item_type));
        }

        $expire = array();
        if(!empty($expiration)){
            $expire = array('expiration' => $expiration);
        }

        $response = $this->travel->post($this->url.'/'.$this->version.'/update', array_merge([
            'id' => $id,
            'name' => $name,
            'folder' => $folderPath,
            'metadata' => $metadata,
            'tags' => $tags,
            'rotation_frequency' => $rotation_frequency,
            'rotation_state' => $rotation_state,
            'expiration' => $expiration,
            'item_state' => $item_state
        ], $expire));
        return $response;
    }

    //Delete a secret, key or folder.
    public function delete($id){
        $response = $this->travel->post($this->url.'/'.$this->version.'/delete', [
            'id' => $id,
        ]);
        return $response;
    }

    public function changeState(string $id, string $state, string $destroy_period = '1d'){
        $response = $this->travel->post($this->url.'/'.$this->version.'/state/change', [
            'id' => $id,
            'state' => $state,
            'destroy_period' => $destroy_period
        ]);
        return $response;
    }
}