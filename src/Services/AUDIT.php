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

class AUDIT implements PangeaInterface {

    protected $travel;

    protected $version;
    
    protected $url;
    //Use event keys for creating your event log. Only use the keys you have registered from your Pangea account when creating secure audit log.
    public $eventKeys = ["actor", "action", "message", "received_at", "source", "status", "target", "timestamp"];

    public function setParentProperties(\Pangea\Pangea $parent, $endpoint){
        $this->travel = $parent;
        $this->version = 'v2';
        $this->url = $endpoint;
    }

    public function log(object $events, string $configID = ""){

        $response = $this->travel->post($this->url.'/'.$this->version.'/log', [
            'events' => $events,
            'config_id' => $configID,
            'verbose' => true,
        ]);
        return $response;
    }

    public function  log_async(object $events, string $configID = ""){

        $response = $this->travel->post($this->url.'/'.$this->version.'/log_async', [
            'events' => $events,
            'config_id' => $configID,
            'verbose' => true,
        ]);
        return $response;
    }

    public function  search_log(string $query, string $configID = "", string $start, string $end = '', int $max_results = 20, int $limit = 0,  string $order = 'asc', string $order_by = 'name', object $search_restriction = new \stdClass()){

        $order_type = ["asc", "desc"];
    
        if (!in_array(strtolower($order), $order_type)) {
            throw new \Exception('Invalid order type. Please choose from the allowed order types ' . implode(', ', $order_type));
        }

        if (!in_array(strtolower($order_by), $this->eventKeys)) {
            throw new \Exception('Invalid order by type. Please choose from the allowed order by types ' . implode(', ', $this->eventKeys));
        }

        $response = $this->travel->post($this->url.'/'.$this->version.'/log_async', [
            'query' => $query,
            'config_id' => $configID,
            'start' => $start,
            'end' => $end,
            'max_results' => $max_results,
            'limit' => $limit,
            'order' => $order,
            'order_by' => $order_by,
            'search_restriction' => $search_restriction,
            'verbose' => true,
        ]);
        return $response;
    }

   

   
}