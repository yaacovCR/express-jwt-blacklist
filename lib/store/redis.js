'use strict';

/**
 * Redis store
 * https://github.com/NodeRedis/node_redis
 */
var redis = require('redis');

var blacklist = require('../');
var debug = require('../debug').log;

module.exports = function(store) {
  var host = store.host || '127.0.0.1';
  var port = store.port || 6379;
  
  var client = store.client || redis.createClient(port, host, store.options || {});
  client.on('error', error);
  
  return {
    set: function(key, value, lifetime, fn) {
      client.set(key, value, fn);
      if (lifetime) client.expire(key, lifetime);
    },
    mget: function(keys, fn) {
      client.mget(keys, function(err, replies) {
        var res = {};
        for (var i = 0; i < keys.length; i++) res[keys[i]] = replies[i];
        fn(err, res);
      });
    }
  }
};

function error(err) {
  debug('Redis: ' + err);
}
