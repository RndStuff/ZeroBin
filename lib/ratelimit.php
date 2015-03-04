<?php

namespace zerobin;


class ratelimit {

    private $request_limit;  // number of seconds of delay between requests

    private $cache_path;
    private $cache;

    /**
     * @param $cache_path string    path to the cache file
     * @param $limit int            delay in seconds between two requests
     */
    function __construct($cache_path, $limit) {
        $this->cache_path = $cache_path;
        $this->request_limit = $limit;

        if (!is_file($cache_path))
            $this->init();
        $this->load();
    }

    function init() {
        $this->cache = [];

        file_put_contents($this->cache_path, serialize($this->cache), LOCK_EX);
        chmod($this->cache_path, 0600);
    }

    function load() {
        $this->cache = unserialize(file_get_contents($this->cache_path));
        $this->prune();
    }

    function save() {
        file_put_contents($this->cache_path, serialize($this->cache), LOCK_EX);
    }

    function prune() {
        $now = time();
        foreach($this->cache as $key => $last_action) {
            if ($now - $this->request_limit >= $last_action)
                unset($this->cache[$key]);
        }
    }

    /**
     * @param $key string   key, identifying a user (for example an IP-Address)
     * @return bool
     */
    function check($key) {
        if (empty($this->cache) || !isset($this->cache[$key]) || time() - $this->request_limit >= $this->cache[$key]) {
            $this->cache[$key] = time();
            $this->save();
            return true;
        }
        return false;
    }

    function getLimit() {
        return $this->request_limit;
    }

    function __deconstruct() {
        $this->save();
    }
}