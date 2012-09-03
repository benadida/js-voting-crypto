//
// some utilities
//

function copyInto(oldObj, newObj) {
  for (var k in oldObj) {
    if (oldObj.hasOwnProperty(k)) newObj[k] = oldObj[k];
  }
}

function getDate(d) {
  if (!d)
    return null;

  var r = new Date();
  r.setTime(d);
  return r;
}

// delay a function
function delay(cb) {
  var delayedFunction = function() {
    var funcArguments = arguments;
    process.nextTick(function() {
      cb.apply(cb, funcArguments);
    });
  };

  return delayedFunction;
}

exports.copyInto = copyInto;
exports.getDate = getDate;
exports.delay = delay;