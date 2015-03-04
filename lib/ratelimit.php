<?php

namespace zerobin;


class ratelimit {

    private $requests_per_second;

    private $cache_path;
    private $cache;

    /**
     * @param $cache_path string    path to the cache file
     * @param $limit int            delay in seconds between two requests
     */
    function __construct($cache_path, $limit) {
        $this->cache_path = $cache_path;
        $this->requests_per_second = $limit;

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
        foreach($this->cache as $addr => $last_action) {
            if ($now - $this->requests_per_second >= $last_action)
                unset($this->cache[$addr]);
        }
    }

    /**
     * @param $key string   key, identifying a user (for example an IP-Address)
     * @return bool
     */
    function check($key) {
        if (empty($this->cache) || !isset($this->cache[$key]) || time() - $this->requests_per_second >= $this->cache[$key]) {
            $this->cache[$key] = time();
            $this->save();
            return true;
        }
        return false;
    }

    function getLimit() {
        return $this->requests_per_second;
    }

    function __deconstruct() {
        $this->save();
    }
}