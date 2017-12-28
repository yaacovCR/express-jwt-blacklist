/*globals describe, it, before*/
'use strict';

var should = require('should');

var blacklist = require('../lib');

var JWT_USER = {
  iat: 1439336202,
  exp: 1439412707,
  sub: '9007F3DA-4081-11E5-9E31-A62DD5902334'
};

var cache = {};

describe('Blacklist custom store', function() {  
  before(function() {
    blacklist.configure({
      store: {
        mget: function(keys, callback) {
          var data = {};
          for (var i = 0; i < keys.length; i++) {
            var key = keys[i];
            data[key] = cache[key];
          };
          callback(null, data);
        },
        set: function(key, data, lifetime, callback) {
          callback(null, cache[key] = data);
        }
      }
    });
  });
  
  it('isRevoked should return false', function(done) {
    blacklist.isRevoked({}, JWT_USER, function(err, revoked) {
      should.not.exist(err);
      revoked.should.be.false();
      done();
    });
  });
  
  it('revoke should revoke JWT token', function(done) {
    blacklist.revoke(JWT_USER, function(err, revoked) {
      should.not.exist(err);
      done();
    });
  });
  
  it('isRevoked should return true', function(done) {
    blacklist.isRevoked({}, JWT_USER, function(err, revoked) {
      should.not.exist(err);
      revoked.should.be.true();
      done();
    });
  });
});