<?php
namespace Pangea\Services;
/**
 * Provides secure storage of secrets, cryptographic keys, and Pangea API Tokens tokens as Vault items. Easily generate, import, and manage secrets and keys to stay compliant and secure.
 *
 * @link https://pangea.cloud/ 
 * @author Manomite Limited <manomitehq@gmail.com>
 * @version 1.0.0
 */

class Vault extends \Pangea {

    private $allowed_type = ["symmetric_key", "asymmetric_key"];
    private $allowed_purpose = ["signing", "encryption", "jwt"];
    private $allowed_state = ["active", "deactivated", "destroyed", "inherited", "suspended", "compromised"];

    public function __construct($token, $service, $csp, $region){
        parent::__construct($token, $service, $csp, $region);
    }
    
    public function generateKey(string $type, string $purpose = "signing", string $keyName = null, string $folderName = null, array $metadata = array(), string | array $tags = null, string $rotation_frequency = '10d', string $rotation_state = 'inherited', string $expiration = null){
        if (!in_array(strtolower($type), $this->allowed_type)) {
            throw new \Exception('Invalid key type. Please choose from the allowed key types ' . implode(', ', $this->allowed_type));
        }
        if (!in_array(strtolower($purpose), $this->allowed_purpose)) {
            throw new \Exception('Invalid purpose type. Please choose from the allowed purpose types ' . implode(', ', $this->allowed_purpose));
        }
        if (!in_array(strtolower($rotation_state), $this->allowed_state)) {
            throw new \Exception('Invalid rotation state. Please choose from the allowed state types ' . implode(', ', $this->allowed_state));
        }
        $response = $this->post('/'.$this->version.'/key/generate', [
            'type' => $type,
            'purpose' => $purpose,
            'name' => $keyName,
            'folder' => $folderName,
            'metadata' => $metadata,
            'tags' => $tags,
            'rotation_frequency' => $rotation_frequency,
            'rotation_state' => $rotation_state,
            'expiration' => $expiration,
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }

    public function rotateKey($id, string $rotation_state = 'inherited'){
        if (!in_array(strtolower($rotation_state), $this->allowed_state)) {
            throw new \Exception('Invalid rotation state. Please choose from the allowed state types ' . implode(', ', $this->allowed_state));
        }
        $response = $this->post('/'.$this->version.'/key/rotate', [
            'id' => $id,
            'rotation_state' => $rotation_state,
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }

    public function encrypt($id, string $text, string $additional_data = null){
        $response = $this->post('/'.$this->version.'/key/encrypt', [
            'id' => $id,
            'plain_text' => $text,
            'additional_data' => $additional_data,
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }

    public function decrypt($id, string $cipher, string $additional_data = null){
        $response = $this->post('/'.$this->version.'/key/decrypt', [
            'id' => $id,
            'cipher_text' => $cipher,
            'additional_data' => $additional_data,
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }

    public function sign($id, string $message){
        $response = $this->post('/'.$this->version.'/key/sign', [
            'id' => $id,
            'message' => $message,
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }

    public function verify($id, string $message, string $signature){
        $response = $this->post('/'.$this->version.'/key/verify', [
            'id' => $id,
            'message' => $message,
            'signature' => $signature,
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }

    public function store(string $type, string $purpose = "signing", string $public_key, $private_key, string $keyName = null, string $folderName = null, array $metadata = array(), string | array $tags = null, string $rotation_frequency = '10d', string $rotation_state = 'inherited', string $expiration = null){
       
        if (!in_array(strtolower($type), $this->allowed_type)) {
            throw new \Exception('Invalid key type. Please choose from the allowed key types ' . implode(', ', $this->allowed_type));
        }
        if (!in_array(strtolower($purpose), $this->allowed_purpose)) {
            throw new \Exception('Invalid purpose type. Please choose from the allowed purpose types ' . implode(', ', $this->allowed_purpose));
        }
        if (!in_array(strtolower($rotation_state), $this->allowed_state)) {
            throw new \Exception('Invalid rotation state. Please choose from the allowed state types ' . implode(', ', $this->allowed_state));
        }
        $response = $this->post('/'.$this->version.'/key/store', [
            'type' => $type,
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
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }

    public function createFolder($folderName, string $path, array $metadata = null, string | array $tags = null, string $rotation_frequency = '10d', string $rotation_state = 'inherited', string $expiration = null){
        $response = $this->post('/'.$this->version.'/folder/create', [
            'name' => $folderName,
            'folder' => $path,
            'metadata' => $metadata,
            'tags' => $tags,
            'rotation_frequency' => $rotation_frequency,
            'rotation_state' => $rotation_state,
            'expiration' => $expiration,
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }

    public function signJWT($id, string $payload){
        $response = $this->post('/'.$this->version.'/key/sign/jwt', [
            'id' => $id,
            'payload' => $payload,
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }

    public function verifyJWT($jws){
        $response = $this->post('/'.$this->version.'/key/verify/jwt', [
            'jws' => $jws,
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }

    public function getJWT($id){
        $response = $this->post('/'.$this->version.'/key/get/jwt', [
            'id' => $id,
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }

    public function rotateSecret($id, $secret = null){
        $response = $this->post('/'.$this->version.'/key/secret/rotate', [
            'id' => $id,
            'secret' => $secret,
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }

    public function storeSecret($type, $secret = null, string $name = null, string $folderPath = null, array $metadata = array(), string | array $tags = null, string $rotation_frequency = '10d', string $rotation_state = 'inherited', string $rotation_grace_period = '7d', string $expiration = null){

        $allowed_type = ["secret", "pangea_token"];

        if (!in_array(strtolower($type), $allowed_type)) {
            throw new \Exception('Invalid allowed type. Please choose from the allowed types ' . implode(', ', $allowed_type));
        }

        if (!in_array(strtolower($rotation_state), $this->allowed_state)) {
            throw new \Exception('Invalid rotation state. Please choose from the allowed state types ' . implode(', ', $this->allowed_state));
        }

        $response = $this->post('/'.$this->version.'/key/secret/store', [
            'type' => $type,
            'secret' => $secret,
            'name' => $name,
            'folder' => $folderPath,
            'metadata' => $metadata,
            'tags' => $tags,
            'rotation_frequency' => $rotation_frequency,
            'rotation_state' => $rotation_state,
            'expiration' => $expiration,
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }


    //Retrieve a secret, key or folder, and any associated information.
    public function getKey($id, $secret = null){
        $response = $this->post('/'.$this->version.'/get', [
            'id' => $id,
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }

    public function listKey(array $filter, int $size = 20, string $order = 'asc', string $order_by = 'name', string $lastID = null, bool $include_secrets = false, array | string $include = null){

        $order_type = ["asc", "desc"];
        $order_by_type = ["id", "type", "created_at", "algorithm", "purpose", "expiration", "last_rotated", "next_rotation", "name", "folder", "item_state"];

        if (!in_array(strtolower($order), $order_type)) {
            throw new \Exception('Invalid order type. Please choose from the allowed order types ' . implode(', ', $order_type));
        }
        if (!in_array(strtolower($order_by), $order_by_type)) {
            throw new \Exception('Invalid order by type. Please choose from the allowed order by types ' . implode(', ', $order_by_type));
        }

        $response = $this->post('/'.$this->version.'/list', [
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
    public function updateSecret(string $id, string $name = null, string $folderPath = null, array $metadata = array(), string | array $tags = null, string $rotation_frequency = '10d', string $rotation_state = 'inherited', string $rotation_grace_period = '7d', string $expiration = null, string $item_state = 'enabled'){

        $allowed_item_type = ["enabled", "disabled"];

        if (!in_array(strtolower($item_state), $allowed_item_type)) {
            throw new \Exception('Invalid allowed type. Please choose from the allowed types ' . implode(', ', $allowed_item_type));
        }

        $response = $this->post('/'.$this->version.'/update', [
            'id' => $id,
            'name' => $name,
            'folder' => $folderPath,
            'metadata' => $metadata,
            'tags' => $tags,
            'rotation_frequency' => $rotation_frequency,
            'rotation_state' => $rotation_state,
            'expiration' => $expiration,
            'item_state' => $item_state,
            'raw' => true,
            'verbose' => true
        ]);
        return $response;
    }

    //Delete a secret, key or folder.
    public function delete($id){
        $response = $this->post('/'.$this->version.'/delete', [
            'id' => $id,
        ]);
        return $response;
    }

    public function changeState(string $id, string $state, string $destroy_period = '1d'){
        $response = $this->post('/'.$this->version.'/state/change', [
            'id' => $id,
            'state' => $state,
            'destroy_period' => $destroy_period
        ]);
        return $response;
    }
}