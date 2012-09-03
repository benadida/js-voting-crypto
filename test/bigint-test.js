var
vows = require('vows'),
assert = require('assert'),
BigInt = require('../lib/bigint').BigInt;

var suite = vows.describe('BigInt tests');

suite.addBatch({
  "create bigint": {
    topic: function() {
      return new BigInt("123456", 10);
    },
    "looks good": function(bi) {
      assert.isObject(bi);
    }
  }
});

suite.export(module);
