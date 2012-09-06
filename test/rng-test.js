var
vows = require('vows'),
assert = require('assert'),
rng = require('../lib/rng'),
BigInt = require("../lib/bigint").BigInt;

var suite = vows.describe('RNG tests');

suite.addBatch({
  "create rng": {
    topic: function() {
      return new rng.RNG();
    },
    "looks good": function(rng) {
      assert.isObject(rng);
      assert.isFunction(rng.addEntropy);
      assert.isFunction(rng.autoseed);
      assert.isFunction(rng.nextBytes);
    },
    "and when we seed": {
      topic: function(rng) {
        rng.addEntropy("foobar");
        return null;
      },
      "all is well": function() {
        assert.ok(true);
      }
    },
    "and when we autoseed": {
      topic: function(rng) {
        rng.autoseed(this.callback);
      },
      "eventually returns": function() {
        assert.ok(true);
      },
      "and when we get random bytes": {
        topic: function(rng) {
          var bytes = [0,0,0,0,0,0,0,0,0,0];
          rng.nextBytes(bytes);
          return bytes;
        },
        "contains stuff": function(bytes) {
          assert.isArray(bytes);
        },
        "and that stuff is random'ish": function(bytes) {
          // this test is unlikely to fail unless no randomness is getting out
          assert.ok(!(bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0));
        }
      },
      "and when we get a random integer": {
        topic: function(rng) {
          var max = new BigInt("123456789123456789123456789123456789123456789");
          return rng.randomInteger(max);
        },
        "returns a bigint": function(bi) {
          assert.isObject(bi);
          assert.isString(bi.toString());
        },
        "in the right range": function(bi) {
          var max = new BigInt("123456789123456789123456789123456789123456789");
          assert.equal(max.max(bi), max);
          
          // could fail, but unlikely
          var bitlength_diff = max.bitLength() - bi.bitLength();
          assert.ok(bitlength_diff < 30);
        }
      }
    }
  }    
});

suite.export(module);
