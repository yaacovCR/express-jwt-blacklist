'use strict';
/**
 * JWT token should contain issued at timestamp `iat`, a unique identifier representing the
 * user (default: `sub`, configurable using the `tokenId` configuration setting), and an
 * additional unique identifier specified by the `indexBy` argument representing the session
 * (default: `iat`, configurable using the `indexBy` setting). We can use that to store
 * information.
 * 
 * For example, using the default configuration settings:
 * 
 * Just the presence of any keys within the store based on `sub` and `iat` can represent a
 * revoked token:
 * 
 *    ae234b24-f2bd-11e4-a6ec-7cdb000003fb:1431020932 {}
 *    ae234b24-f2bd-11e4-a6ec-7cdb000003fb:1431021232 {}
 * 
 * For purges, a key based on `sub` can store the value of the latest purged `iat`.
 *  
 *    ae234b24-f2bd-11e4-a6ec-7cdb000003fb: {1431021532}
 * 
 * Consider a a token with payload:
 * 
 * {
 *   sub: ae234b24-f2bd-11e4-a6ec-7cdb000003fb:1431020932,
 *   iat: 1431021832
 * }
 * 
 * isRevoked middleware works like this:
 * 
 *  - Key 234b24-f2bd-11e4-a6ec-7cdb000003fb:1431021832 does not exist in the store, so the
 *    token had not been individually revoked.
 *  - Key 234b24-f2bd-11e4-a6ec-7cdb000003fb does exist in the store, but `iat` is later than
 *    the stored value.
 * 
 * So the token passes!
 * 
 * Considerations
 * 
 * 1. Issued at timestamp(in seconds) is not ideal way to ensure uniqueness and can cause collision
 *    in extreme cases but since it's in the context of a single user it should have no effect.
 * 2. There's no need to store the blacklist data indefinitely since the JWT tokens have expiration built in.
 *    Store expiration is set to match the token expiration.
 * 3. Purges don't invalidate all tokens except for the next one issued, they invalidate all old tokens, and
 *    so if a token is being refreshed pseudo-simultaneously as the purge operation, it will escape the purge.
 *    A purge that includes the current time with a whitelist would address this edge case.
 */

var debug = require('./debug').log;
var utils = require('./utils');

// Defaults
var store = require('./store')({type: 'memory'});
var tokenId = 'sub';
var indexBy = 'iat';
var keyPrefix = 'jwt-blacklist:';
var strict = false;

/**
 * Session revocation operations:
 * 
 *  - revoke: revoke a single token
 *  - purge:  revoke all tokens issues prior to the current time
 */
var TYPE = {
  revoke: 'revoke',
  purge: 'purge'
};

/**
 * Configuration
 * 
 * @param {String} opts.store.type      Store type
 * @param {String} opts.store.host      Store host
 * @param {String} opts.store.port      Store port
 * @param {String} opts.store.keyPrefix Store key prefix
 * @param {String} opts.store.options   Store client options
 * @param {String} opts.tokenId         Unique JWT token identifier
 * @param {String} opts.strict          Strict mode
 */
exports.configure = function(opts) {
  opts = opts || {};
  
  if (opts.store) {
    if (opts.store.type) {
      store = require('./store')(opts.store);

      if (opts.store.keyPrefix) {
        utils.checkString(opts.store.keyPrefix, 'keyPrefix');
        keyPrefix = opts.store.keyPrefix;
      }
    }
    else if (typeof opts.store.mget === 'function' && typeof opts.store.set === 'function') {
      store = opts.store;
    }
  }
  
  if (opts.tokenId) {
    utils.checkString(opts.tokenId, 'tokenId');
    tokenId = opts.tokenId;
  }
  if (opts.indexBy) {
    utils.checkString(opts.indexBy, 'indexBy');
    indexBy = opts.indexBy;
  }
  if (opts.strict) {
    utils.checkBoolean(opts.strict, 'strict');
    strict = opts.strict;
  }
};

/**
 * Check if JWT token is revoked
 * 
 * @param   {Object}   req  Express request object
 * @param   {Object}   user Express JWT user object
 * @param   {Function} fn   Callback function
 */
exports.isRevoked = middleware;

/**
 * Revoke a single JWT token
 * 
 * @param   {Object}   user JWT user payload
 * @param   {Number}   Optional lifetime (in seconds) for this entry
 * @param   {Function} [fn] Optional callback function
 */
exports.revoke = operation.bind(null, TYPE.revoke);

/**
 * Pure all existing JWT tokens
 * 
 * @param   {Object}   user JWT user payload
 * @param   {Number}   Optional lifetime (in seconds) for this entry
 * @param   {Function} [fn] Optional callback function
 */
exports.purge = operation.bind(null, TYPE.purge);

/**
 * Enable/disable debugging
 */
exports.__defineSetter__('debug', function(val) {
  require('./debug').debug = !!val;
});

function middleware(req, user, fn) {
  debug('middleware [user]', user);

  var id = user[tokenId];
  if (!id) return fn(new Error('JWT missing tokenId claim ' + tokenId));
  var index = user[indexBy];
  if (!index) return fn(new Error('JWT missing indexBy claim ' + indexBy));
  
  var purged = keyPrefix + ':' + id;
  var revoked = keyPrefix + ':' + id + ':' + index;
  store.mget([purged, revoked], function(err, res) {
    if (err) {
      debug('middleware [' + key + '] error:', err);
      return fn(null, strict);    
    }
    debug('middleware [' + purged + ']', res[purged]);
    debug('middleware [' + revoked + ']', res[revoked]);
    if (res[purged] >= user.iat) fn(null, true);
    else fn(null, res[revoked] === '');
  });
};

function operation(type, user, lifetime, fn) {
  if (typeof fn !== 'function') fn = utils.optionalCallback;
  if (typeof lifetime === 'function') {
    fn = lifetime;
    lifetime = undefined;   
  } else if (lifetime && typeof lifetime !== 'number') {
    return fn(new Error('Invalid lifetime value'));
  }
  if (!user) return fn(new Error('User payload missing'));
  if (!lifetime && typeof user.iat !== 'number') return fn(new Error('Invalid user.iat value'));
  
  var id = user[tokenId];
  if (!id) return fn(new Error('JWT missing tokenId claim' + tokenId));

  lifetime = lifetime ? lifetime : (user.exp ? user.exp - user.iat : 0);

  debug('operation [' + type + ']', {user: user, lifetime: lifetime});

  if (type === TYPE.purge) {

    var key = keyPrefix + ':' + id;
    var data = utils.nowInSeconds() - 1;

  } else if (type === TYPE.revoke) {

    var index = user[indexBy];
    if (!index) return fn(new Error('JWT missing indexBy claim' + tokenId));
    var key = keyPrefix + ':' + id + ':' + index;
    var data = '';
    
  }
  store.set(key, data, lifetime, fn);
};
