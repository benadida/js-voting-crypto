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
  },
  "add bigints": {
    topic: function() {
      var a = new BigInt("10000000000000000000000000004", 10);
      var b = new BigInt("20000000000000040000000000008", 10);
      return a.add(b);
    },
    "gives the right result": function(sum) {
      assert.ok(sum.equals(new BigInt("30000000000000040000000000012", 10)));
    }
  }
});

suite.export(module);
