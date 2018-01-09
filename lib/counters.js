'use strict';

const fs = require('fs');
const ttlCounterScript = fs.readFileSync(__dirname + '/lua/ttlcounter.lua', 'utf-8');
const cachedCounterScript = fs.readFileSync(__dirname + '/lua/cachedcounter.lua', 'utf-8');
const limitedCounterScript = fs.readFileSync(__dirname + '/lua/limitedcounter.lua', 'utf-8');

const clientVersion = Date.now();

/*
    redis.defineCommand('echoDynamicKeyNumber', {
      lua: 'return {KEYS[1],KEYS[2],ARGV[1],ARGV[2]}'
    });

    // Now you have to pass the number of keys as the first argument every time
    // you invoke the `echoDynamicKeyNumber` command:
    redis.echoDynamicKeyNumber(2, 'k1', 'k2', 'a1', 'a2', function (err, result) {
      // result === ['k1', 'k2', 'a1', 'a2']
    });
 */

module.exports = redis => {
    redis.defineCommand('ttlcounter', {
        //the number of keys. If omit, you have to pass the number of keys as the first argument every time you invoke the command
        numberOfKeys: 1,
        lua: ttlCounterScript
    });

    redis.defineCommand('cachedcounter', {
        numberOfKeys: 1,
        lua: cachedCounterScript
    });

    redis.defineCommand('limitedcounter', {
        numberOfKeys: 1,
        lua: limitedCounterScript
    });

    return {
        /**
         *
         * @param key redis key,
         *          forward: 'wdf:' + userData._id
         *          autoreply: 'wda:' + userData._id
         * @param count 当前要增加的值
         * @param max 最大限制的值
         * @param windowSize 超时时间，默认一天
         * @param callback
         * @returns {*}
         */
        ttlcounter(key, count, max, windowSize, callback) {
            if (!max || isNaN(max)) {
                return callback(null, {
                    success: true,
                    value: 0,
                    ttl: 0
                });
            }
            /*
                key: KEY[1]
                count: ARGV[1]
                max: ARGV[2]
                windowSize: ARGV[3]
             */
            redis.ttlcounter(key, count, max, windowSize || 86400, (err, res) => {
                if (err) {
                    return callback(err);
                }
                return callback(null, {
                    success: !!((res && res[0]) || 0),
                    value: (res && res[1]) || 0,
                    ttl: (res && res[2]) || 0
                });
            });
        },

        cachedcounter(key, count, ttl, callback) {
            redis.cachedcounter(key, count, ttl, (err, res) => {
                if (err) {
                    return callback(err);
                }
                callback(null, res);
            });
        },

        limitedcounter(key, entry, count, limit, callback) {
            redis.limitedcounter(key, entry, count, limit, clientVersion, (err, res) => {
                if (err) {
                    return callback(err);
                }
                return callback(null, {
                    success: !!((res && res[0]) || 0),
                    value: (res && res[1]) || 0
                });
            });
        }
    };
};
