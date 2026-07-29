import assert from 'assert';
import utils from '../../../lib/utils.js';
import mergeConfig from '../../../lib/core/mergeConfig.js';

describe('Prototype Pollution Protection', function () {
  afterEach(function () {
    // Clean up any pollution that might have occurred
    delete Object.prototype.polluted;
  });

  describe('utils.merge', function () {
    it('should filter __proto__ key at top level', function () {
      const result = utils.merge({}, {__proto__: {polluted: 'yes'}, safe: 'value'});

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.safe, 'value');
      assert.strictEqual(result.hasOwnProperty('__proto__'), false);
    });

    it('should filter constructor key at top level', function () {
      const result = utils.merge({}, {constructor: {polluted: 'yes'}, safe: 'value'});

      assert.strictEqual(result.safe, 'value');
      assert.strictEqual(result.hasOwnProperty('constructor'), false);
    });

    it('should filter prototype key at top level', function () {
      const result = utils.merge({}, {prototype: {polluted: 'yes'}, safe: 'value'});

      assert.strictEqual(result.safe, 'value');
      assert.strictEqual(result.hasOwnProperty('prototype'), false);
    });

    it('should filter __proto__ key in nested objects', function () {
      const result = utils.merge({}, {
        headers: {
          __proto__: {polluted: 'nested'},
          'Content-Type': 'application/json'
        }
      });

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers['Content-Type'], 'application/json');
      assert.strictEqual(result.headers.hasOwnProperty('__proto__'), false);
    });

    it('should filter constructor key in nested objects', function () {
      const result = utils.merge({}, {
        headers: {
          constructor: {prototype: {polluted: 'nested'}},
          'Content-Type': 'application/json'
        }
      });

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers['Content-Type'], 'application/json');
      assert.strictEqual(result.headers.hasOwnProperty('constructor'), false);
    });

    it('should filter prototype key in nested objects', function () {
      const result = utils.merge({}, {
        headers: {
          prototype: {polluted: 'nested'},
          'Content-Type': 'application/json'
        }
      });

      assert.strictEqual(result.headers['Content-Type'], 'application/json');
      assert.strictEqual(result.headers.hasOwnProperty('prototype'), false);
    });

    it('should filter dangerous keys in deeply nested objects', function () {
      const result = utils.merge({}, {
        level1: {
          level2: {
            __proto__: {polluted: 'deep'},
            prototype: {polluted: 'deep'},
            safe: 'value'
          }
        }
      });

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.level1.level2.safe, 'value');
      assert.strictEqual(result.level1.level2.hasOwnProperty('__proto__'), false);
    });

    it('should still merge regular properties correctly', function () {
      const result = utils.merge({a: 1, b: {c: 2}}, {b: {d: 3}, e: 4});

      assert.strictEqual(result.a, 1);
      assert.strictEqual(result.b.c, 2);
      assert.strictEqual(result.b.d, 3);
      assert.strictEqual(result.e, 4);
    });

    it('should handle JSON.parse payloads safely', function () {
      const malicious = JSON.parse('{"__proto__": {"polluted": "yes"}}');
      const result = utils.merge({}, malicious);

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.hasOwnProperty('__proto__'), false);
    });

    it('should handle nested JSON.parse payloads safely', function () {
      const malicious = JSON.parse('{"headers": {"constructor": {"prototype": {"polluted": "yes"}}}}');
      const result = utils.merge({}, malicious);

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers.hasOwnProperty('constructor'), false);
    });
  });

  describe('mergeConfig', function () {
    it('should filter dangerous keys at top level', function () {
      const result = mergeConfig({}, {
        __proto__: {polluted: 'yes'},
        constructor: {polluted: 'yes'},
        prototype: {polluted: 'yes'},
        url: '/api/test'
      });

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.url, '/api/test');
      assert.strictEqual(result.hasOwnProperty('__proto__'), false);
      assert.strictEqual(result.hasOwnProperty('constructor'), false);
      assert.strictEqual(result.hasOwnProperty('prototype'), false);
    });

    it('should filter dangerous keys in headers', function () {
      const result = mergeConfig({}, {
        headers: {
          __proto__: {polluted: 'yes'},
          'Content-Type': 'application/json'
        }
      });

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers['Content-Type'], 'application/json');
      assert.strictEqual(result.headers.hasOwnProperty('__proto__'), false);
    });

    it('should filter dangerous keys in custom config properties', function () {
      const result = mergeConfig({}, {
        customProp: {
          __proto__: {polluted: 'yes'},
          safe: 'value'
        }
      });

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.customProp.safe, 'value');
      assert.strictEqual(result.customProp.hasOwnProperty('__proto__'), false);
    });

    it('should still merge configs correctly', function () {
      const config1 = {
        baseURL: 'https://api.example.com',
        timeout: 1000,
        headers: {
          common: {
            Accept: 'application/json'
          }
        }
      };

      const config2 = {
        url: '/users',
        timeout: 5000,
        headers: {
          common: {
            'Content-Type': 'application/json'
          }
        }
      };

      const result = mergeConfig(config1, config2);

      assert.strictEqual(result.baseURL, 'https://api.example.com');
      assert.strictEqual(result.url, '/users');
      assert.strictEqual(result.timeout, 5000);
      assert.strictEqual(result.headers.common.Accept, 'application/json');
      assert.strictEqual(result.headers.common['Content-Type'], 'application/json');
    });
  });

  describe('denial of service through Object.prototype keys', function () {
    const hasOwn = (obj, prop) => Object.prototype.hasOwnProperty.call(obj, prop);

    it('should not crash when both configs carry an own __proto__ property', function () {
      // `Object.assign` drops config1's own `__proto__` onto the prototype of the
      // accumulator, which then exposes config2's `__proto__` as an own key.
      const config1 = JSON.parse('{"__proto__": null}');
      const config2 = JSON.parse('{"__proto__": {"polluted": "yes"}, "url": "/api/test"}');

      let result;
      try {
        result = mergeConfig(config1, config2);
      } catch (err) {
        assert.fail('mergeConfig threw on an own __proto__ property: ' + err.message);
      }

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.url, '/api/test');
      assert.strictEqual(Object.getPrototypeOf(result), Object.prototype);
      assert.strictEqual(hasOwn(result, '__proto__'), false);
    });

    it('should not resolve merge strategies from Object.prototype', function () {
      const inheritedNames = [
        'toString',
        'valueOf',
        'hasOwnProperty',
        'isPrototypeOf',
        'propertyIsEnumerable',
        'toLocaleString',
        '__defineGetter__',
        '__defineSetter__',
        '__lookupGetter__',
        '__lookupSetter__'
      ];

      inheritedNames.forEach(function (name) {
        const config2 = JSON.parse('{"' + name + '": 1, "url": "/api/test"}');

        let result;
        try {
          result = mergeConfig({}, config2);
        } catch (err) {
          assert.fail('mergeConfig threw on an own "' + name + '" property: ' + err.message);
        }

        assert.strictEqual(result.url, '/api/test');
        assert.strictEqual(result[name], 1);
      });
    });

    it('should not let the merged object inherit attacker controlled data', function () {
      const result = utils.merge({}, JSON.parse('{"__proto__": {"baseURL": "http://attacker.example"}}'));

      assert.strictEqual(Object.getPrototypeOf(result), Object.prototype);
      assert.strictEqual(result.baseURL, undefined);
      assert.strictEqual(Object.prototype.baseURL, undefined);
    });

    it('should not let a caseless merge inherit attacker controlled data', function () {
      const result = utils.merge.call({caseless: true}, {}, JSON.parse('{"__proto__": {"Authorization": "leak"}}'));

      assert.strictEqual(Object.getPrototypeOf(result), Object.prototype);
      assert.strictEqual(result.Authorization, undefined);
    });
  });
});
