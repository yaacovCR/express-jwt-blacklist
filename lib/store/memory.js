'use strict';

/**
 * Simple in-memory cache
 * NOTE: Not recommended for production
 */

var cache = {};

module.exports = function() {
  return {
    set: function(key, value, lifetime, fn) {
      if (cache[key] && cache[key].timeout) clearTimeout(cache[key].timeout);
      cache[key] = {
        data: value,
        timeout: lifetime ? setTimeout(expire.bind(null, key), lifetime * 1000) : null
      };
      fn(null, cache[key].data);
    },
    mget: function(keys, fn) {
      var data = {};
      for (var i = 0; i < keys.length; i++) {
        var key = keys[i];
        data[key] = cache[key] ? cache[key].data : null;
      }
      fn(null, data);
    }
  };
};

function expire(key) {
  delete cache[key];
}