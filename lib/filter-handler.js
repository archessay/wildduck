'use strict';

const log = require('npmlog');
const ObjectID = require('mongodb').ObjectID;
const forward = require('./forward');
const autoreply = require('./autoreply');
const Maildropper = require('./maildropper');
const tools = require('./tools');
const consts = require('./consts');

const defaultSpamHeaderKeys = [
    {
        key: 'X-Spam-Status',
        value: '^yes',
        target: '\\Junk'
    },

    {
        key: 'X-Rspamd-Spam',
        value: '^yes',
        target: '\\Junk'
    },

    {
        key: 'X-Rspamd-Bar',
        value: '^\\+{6}',
        target: '\\Junk'
    },

    {
        key: 'X-Haraka-Virus',
        value: '.',
        target: '\\Junk'
    }
];

class FilterHandler {
    /**
     *  {
     *       db,// db = require('./lib/db');
     *       sender: config.sender,// config = require('wild-config');
     *       messageHandler,
     *       spamHeaderKeys,
     *       spamChecks
     *   }
     * @param options
     */
    constructor(options) {
        this.db = options.db;
        this.messageHandler = options.messageHandler;

        this.spamChecks = options.spamChecks || tools.prepareSpamChecks(defaultSpamHeaderKeys);
        this.spamHeaderKeys = options.spamHeaderKeys || this.spamChecks.map(check => check.key);

        this.senderEnabled = options.sender.enabled;
        this.maildrop = new Maildropper({
            db: this.db,
            zone: options.sender.zone,
            collection: options.sender.collection,
            gfs: options.sender.gfs
        });
    }

    /**
     * 获取收件人信息
     *
     * @param address 收件人 user信息 or 邮箱地址
     * @param callback
     * @returns {*}
     */
    getUserData(address, callback) {

        // 查询条件
        let query = {};

        if (!address) {
            return callback(null, false);
        }
        if (typeof address === 'object' && address._id) {
            return callback(null, address);
        }

        let collection;

        if (typeof address === 'object' && typeof address.getTimestamp === 'function') {
            query._id = address;
            collection = 'users';
        } else if (/^[a-f0-9]{24}$/.test(address)) {
            query._id = new ObjectID(address);
            collection = 'users';
        } else if (typeof address !== 'string') {
            return callback(null, false);
        } else if (address.indexOf('@') >= 0) {
            query.addrview = address.substr(0, address.indexOf('@')).replace(/\./g, '') + address.substr(address.indexOf('@'));
            collection = 'addresses';
        } else {
            query.unameview = address.replace(/\./g, '');
            collection = 'users';
        }

        let fields = {
            name: true,
            forwards: true,
            forward: true,
            targetUrl: true,
            autoreply: true,
            encryptMessages: true,
            encryptForwarded: true,
            pubKey: true
        };

        if (collection === 'users') {
            return this.db.users.collection('users').findOne(
                query,
                {
                    fields
                },
                callback
            );
        }

        return this.db.users.collection('addresses').findOne(query, (err, addressData) => {
            if (err) {
                return callback(err);
            }
            if (!addressData || !!addressData.user) {
                return callback(null, false);
            }
            return this.db.users.collection('users').findOne(
                {
                    _id: addressData.user
                },
                {
                    fields
                },
                callback
            );
        });
    }

    /**
     *
     * @param options
     * @param callback
     */
    process(options, callback) {
        // 获取用户信息
        this.getUserData(options.user || options.recipient, (err, userData) => {
            if (err) {
                return callback(err);
            }
            if (!userData) {
                return callback(null, false);
            }

            this.storeMessage(userData, options, callback);
        });
    }

    storeMessage(userData, options, callback) {
        let sender = options.sender || '';// 发件人邮箱
        let recipient = options.recipient || userData.address;// 收件人邮箱

        // create Delivered-To and Return-Path headers
        let extraHeader = Buffer.from(['Delivered-To: ' + recipient, 'Return-Path: <' + sender + '>'].join('\r\n') + '\r\n');

        let chunks = options.chunks;
        let chunklen = options.chunklen;

        if (!chunks && options.raw) {
            chunks = [options.raw];
            chunklen = options.raw.length;
        }

        let getPreparedMessage = next => {
            if (options.mimeTree) {// prepare cached
                if (options.mimeTree && options.mimeTree.header) {
                    // remove old headers
                    if (/^Delivered-To/.test(options.mimeTree.header[0])) {// see 02PREPARE.json
                        options.mimeTree.header.shift();
                    }
                    if (/^Return-Path/.test(options.mimeTree.header[0])) {
                        options.mimeTree.header.shift();
                    }
                }

                return this.messageHandler.prepareMessage(
                    {
                        mimeTree: options.mimeTree,
                        indexedHeaders: this.spamHeaderKeys
                    },
                    next
                );
            } else {
                let raw = Buffer.concat(chunks, chunklen);
                return this.messageHandler.prepareMessage(
                    {
                        raw,
                        indexedHeaders: this.spamHeaderKeys
                    },
                    next
                );
            }
        };

        getPreparedMessage((err, prepared) => {
            if (err) {
                return callback(err);
            }

            // 如果使用缓存的 prepare.mimeTree 构建新的 prepare.mimeTree, 需要重置Return-Path、Delivered-To相关信息
            prepared.mimeTree.header.unshift('Return-Path: <' + sender + '>');
            prepared.mimeTree.header.unshift('Delivered-To: ' + recipient);

            prepared.mimeTree.parsedHeader['return-path'] = '<' + sender + '>';
            prepared.mimeTree.parsedHeader['delivered-to'] = '<' + recipient + '>';

            prepared.size = this.messageHandler.indexer.getSize(prepared.mimeTree);

            // from prepared.mimeTree
            let maildata = options.maildata || this.messageHandler.indexer.getMaildata(prepared.mimeTree);

            // default flags are empty
            let flags = [];

            // default mailbox target is INBOX
            let mailboxQueryKey = 'path';
            let mailboxQueryValue = 'INBOX';

            let meta = options.meta || {};

            let received = [].concat((prepared.mimeTree.parsedHeader && prepared.mimeTree.parsedHeader.received) || []);
            if (received.length) {
                let receivedData = parseReceived(received[0]);

                if (!receivedData.has('id') && received.length > 1) {
                    receivedData = parseReceived(received[1]);
                }

                if (receivedData.has('with')) {
                    meta.transtype = receivedData.get('with');
                }

                if (receivedData.has('id')) {
                    meta.queueId = receivedData.get('id');
                }

                if (receivedData.has('from')) {
                    meta.origin = receivedData.get('from');
                }
            }

            this.db.database
                .collection('filters')
                .find({
                    user: userData._id
                })
                .sort({
                    _id: 1
                })
                .toArray((err, filters) => {
                    if (err) {
                        // ignore, as filtering is not so important
                    }

                    // concat user's filters and default filters
                    // see 05FILTERS.json for more details about the concat result
                    filters = (filters || []).concat(
                        this.spamChecks.map((check, i) => ({
                            id: 'SPAM#' + (i + 1),
                            query: {
                                headers: {
                                    [check.key]: check.value
                                }
                            },
                            action: {
                                // only applies if any other filter does not already mark message as spam or ham
                                spam: true
                            }
                        }))
                    );

                    // 用于 encryptMessages， 标记 forward 时，是否对 message 已进行过加密操作
                    let isEncrypted = false;
                    let forwardTargets = new Map();

                    let matchingFilters = [];
                    let filterActions = new Map();

                    filters
                        // see 06MAILDATA.json for maildata details
                        // apply all filters to the message
                        .map(filter => checkFilter(filter, prepared, maildata))
                        // remove all unmatched filters
                        .filter(filter => filter)
                        // apply filter actions
                        .forEach(filter => {
                            matchingFilters.push(filter.id);

                            // apply matching filter
                            Object.keys(filter.action).forEach(key => {
                                if (key === 'forward') {
                                    [].concat(filter.action[key] || []).forEach(address => {
                                        forwardTargets.set(address, { type: 'mail', value: address });
                                    });
                                    return;
                                }

                                if (key === 'targetUrl') {
                                    [].concat(filter.action[key] || []).forEach(address => {
                                        forwardTargets.set(address, { type: 'http', value: address });
                                    });
                                    return;
                                }

                                // if a previous filter already has set a value then do not touch it
                                if (!filterActions.has(key)) {
                                    filterActions.set(key, filter.action[key]);
                                }
                            });
                        });

                    /**
                     * 以下情况，会继续执行forward:
                     *      1. 用户设置不加密 or pubKey 不存在；
                     *      2. 加密失败，则会继续使用明文 chunks ；
                     * 特别的，
                     *      如果通过加密的 chunks 生成 prepare message 失败，则中止forward，并callback
                     *
                     * @param condition
                     * @param next
                     * @returns {*}
                     */
                    let encryptMessage = (condition, next) => {
                        if (!condition || isEncrypted) {
                            return next();
                        }

                        this.messageHandler.encryptMessage(
                            userData.pubKey,
                            {
                                chunks,
                                chunklen
                            },
                            (err, encrypted) => {
                                if (err) {
                                    return next();
                                }
                                if (encrypted) {
                                    chunks = [encrypted];
                                    chunklen = encrypted.length;
                                    isEncrypted = true;

                                    return this.messageHandler.prepareMessage(
                                        {
                                            raw: Buffer.concat([extraHeader, encrypted]),
                                            indexedHeaders: this.spamHeaderKeys
                                        },
                                        (err, preparedEncrypted) => {
                                            if (err) {
                                                return callback(err);
                                            }
                                            prepared = preparedEncrypted;
                                            maildata = this.messageHandler.indexer.getMaildata(prepared.mimeTree);
                                            next();
                                        }
                                    );
                                }

                                next();
                            }
                        );
                    };

                    /**
                     * 以下条件之一不满足，不执行forward:
                     *      1. senderEnabled of config is false;
                     *      2. filterActions has spam;
                     *      3. ttlcounter's result.success is false;
                     * 特别的，
                     *      1. forward to default recipient only if the message is not deleted;
                     *      2. forward to default URL only if the message is not deleted
                     *
                     * @param done
                     * @returns {*}
                     */
                    let forwardMessage = done => {
                        if (!this.senderEnabled) {
                            return setImmediate(done);
                        }

                        if (userData.forward && !filterActions.get('delete')) {
                            // forward to default recipient only if the message is not deleted
                            (Array.isArray(userData.forward) ? userData.forward : [].concat(userData.forward || [])).forEach(forward => {
                                if (forward) {
                                    forwardTargets.set(forward, { type: 'mail', value: forward });
                                }
                            });
                        }

                        if (userData.targetUrl && !filterActions.get('delete')) {
                            // forward to default URL only if the message is not deleted
                            forwardTargets.set(userData.targetUrl, { type: 'http', value: userData.targetUrl });
                        }

                        // forwardTargets is Null, never forward
                        // never forward messages marked as spam
                        if (!forwardTargets.size || filterActions.get('spam')) {
                            return setImmediate(done);
                        }

                        // check limiting counters
                        // 通过 forwards 限制 forward 的次数，默认 24小时 只允许转发 userData.forwards 次
                        this.messageHandler.counters.ttlcounter(
                            'wdf:' + userData._id.toString(),
                            forwardTargets.size,
                            userData.forwards || consts.MAX_FORWARDS,
                            false,
                            (err, result) => {
                                if (err) {
                                    // failed checks
                                    log.error('LMTP', 'FRWRDFAIL key=%s error=%s', 'wdf:' + userData._id.toString(), err.message);
                                } else if (!result.success) {
                                    log.silly('LMTP', 'FRWRDFAIL key=%s error=%s', 'wdf:' + userData._id.toString(), 'Precondition failed');
                                    return done();
                                }

                                // 这里针对 encryptForwarded 执行加密
                                encryptMessage(userData.encryptForwarded && userData.pubKey, () => {
                                    // forward logic
                                    forward(
                                        {
                                            db: this.db,
                                            maildrop: this.maildrop,

                                            parentId: prepared.id,
                                            userData,
                                            sender,
                                            recipient,

                                            targets:
                                                (forwardTargets.size &&
                                                    Array.from(forwardTargets).map(row => ({
                                                        type: row[1].type,
                                                        value: row[1].value
                                                    }))) ||
                                                false,

                                            chunks,
                                            chunklen
                                        },
                                        done // callback for forwardMessage(), and return id（用于拼接保存邮件body的文件名称：message id）
                                    );
                                });
                            }
                        );
                    };

                    /**
                     * 以下条件之一不满足，不执行autoreply:
                     *      1. senderEnabled of config is false;
                     *      2. sender is Null;
                     *      3. autoreply is false;
                     *      4. filterActions has spam;
                     *
                     * @param done
                     * @returns {*}
                     */
                    let sendAutoreply = done => {
                        if (!this.senderEnabled) {
                            return setImmediate(done);
                        }

                        // never reply to messages marked as spam
                        if (!sender || !userData.autoreply || filterActions.get('spam')) {
                            return setImmediate(done);
                        }

                        let curtime = new Date();
                        this.db.database.collection('autoreplies').findOne(
                            {
                                user: userData._id,
                                start: {
                                    $lte: curtime
                                },
                                end: {
                                    $gte: curtime
                                }
                            },
                            (err, autoreplyData) => {
                                if (err) {
                                    return callback(err);
                                }

                                if (!autoreplyData || !autoreplyData.status) {
                                    return callback(null, false);
                                }

                                autoreply(
                                    {
                                        db: this.db,
                                        maildrop: this.maildrop,

                                        parentId: prepared.id,
                                        userData,
                                        sender,
                                        recipient,
                                        chunks,
                                        chunklen,
                                        messageHandler: this.messageHandler
                                    },
                                    autoreplyData,
                                    done// callback for sendAutoreply(), and return id（用于拼接保存邮件body的文件名称：message id）
                                );
                            }
                        );
                    };

                    let outbound = [];

                    forwardMessage((err, id) => {
                        if (err) {
                            log.error(
                                'LMTP',
                                '%s FRWRDFAIL from=%s to=%s target=%s error=%s',
                                prepared.id.toString(),
                                sender,
                                recipient,
                                Array.from(forwardTargets)
                                    .map(row => row[0])
                                    .join(','),
                                err.message
                            );
                        } else if (id) {

                            outbound.push(id);

                            log.silly(
                                'LMTP',
                                '%s FRWRDOK id=%s from=%s to=%s target=%s',
                                prepared.id.toString(),
                                id,
                                sender,
                                recipient,
                                Array.from(forwardTargets)
                                    .map(row => row[0])
                                    .join(',')
                            );
                        }

                        sendAutoreply((err, id) => {
                            if (err) {
                                log.error('LMTP', '%s AUTOREPLYFAIL from=%s to=%s error=%s', prepared.id.toString(), '<>', sender, err.message);
                            } else if (id) {
                                outbound.push(id);
                                log.silly('LMTP', '%s AUTOREPLYOK id=%s from=%s to=%s', prepared.id.toString(), id, '<>', sender);
                            }

                            if (filterActions.get('delete')) {
                                // nothing to do with the message, just continue
                                let err = new Error('Message dropped by policy');
                                err.code = 'DroppedByPolicy';

                                return callback(null, {
                                    userData,
                                    response: 'Message dropped by policy as ' + prepared.id.toString(),
                                    error: err
                                });
                            }

                            // apply filter results to the message
                            filterActions.forEach((value, key) => {
                                switch (key) {
                                    case 'spam':
                                        if (value > 0) {
                                            // positive value is spam
                                            mailboxQueryKey = 'specialUse';
                                            mailboxQueryValue = '\\Junk';
                                        }
                                        break;
                                    case 'seen':
                                        if (value) {
                                            flags.push('\\Seen');
                                        }
                                        break;
                                    case 'flag':
                                        if (value) {
                                            flags.push('\\Flagged');
                                        }
                                        break;
                                    case 'mailbox':
                                        if (value) {
                                            mailboxQueryKey = 'mailbox';
                                            mailboxQueryValue = value;
                                        }
                                        break;
                                }
                            });

                            let messageOpts = {
                                user: userData._id,

                                // default mailboxQueryKey is 'path', default  mailboxQueryValue is 'INBOX'
                                [mailboxQueryKey]: mailboxQueryValue,

                                prepared,
                                maildata,

                                meta,

                                filters: matchingFilters,// list filter IDs that matched this message

                                date: false,
                                flags,

                                // if similar message exists, then skip
                                skipExisting: true
                            };

                            // forward and autoreply 's id will push in outbound
                            if (outbound && outbound.length) {
                                messageOpts.outbound = [].concat(outbound || []);
                            }

                            if (forwardTargets.size) {
                                messageOpts.forwardTargets = Array.from(forwardTargets).map(row => ({
                                    type: row[1].type,
                                    value: row[1].value
                                }));
                            }

                            // 这里针对 encryptMessages 执行加密
                            encryptMessage(userData.encryptMessages && userData.pubKey, () => {
                                if (isEncrypted) {
                                    // make sure we have the updated message structure values
                                    messageOpts.prepared = prepared;
                                    messageOpts.maildata = maildata;
                                }

                                this.messageHandler.add(messageOpts, (err, inserted, info) => {
                                    // push to response list
                                    callback(
                                        null,
                                        {
                                            userData,
                                            response: err ? err : 'Message stored as ' + info.id.toString(),
                                            error: err
                                        },
                                        // 只会缓存没有加密的 prepare message
                                        (!isEncrypted && {
                                            // reuse parsed values
                                            mimeTree: messageOpts.prepared.mimeTree,
                                            maildata: messageOpts.maildata
                                        }) ||
                                            false
                                    );
                                });
                            });
                        });
                    });
                });
        });
    }
}

/**
 * 筛选出符合下列条件的filters
 *
 * @param filter
 * @param prepared
 * @param maildata
 * @returns {*}
 */
function checkFilter(filter, prepared, maildata) {
    if (!filter || !filter.query) {
        return false;
    }

    let query = filter.query;

    // prepare filter data
    let headerFilters = new Map();

    // 1. 检查 header
    if (query.headers) {
        Object.keys(query.headers).forEach(key => {
            let value = query.headers[key];
            if (!value || !value.isRegex) {
                value = (query.headers[key] || '').toString().toLowerCase();
            }
            headerFilters.set(key, value);
        });
    }

    // check headers
    if (headerFilters.size) {

        let headerMatches = new Set();

        for (let j = prepared.headers.length - 1; j >= 0; j--) {
            let header = prepared.headers[j];
            if (headerFilters.has(header.key)) {
                let check = headerFilters.get(header.key);
                if (check && check.isRegex && check.test(header.value)) {
                    headerMatches.add(header.key);
                } else if (header.value.indexOf(headerFilters.get(header.key)) >= 0) {
                    headerMatches.add(header.key);
                }
            }
        }
        if (headerMatches.size < headerFilters.size) {
            // not enough matches
            return false;
        }
    }

    // 2. 检查附件
    if (typeof query.ha === 'boolean') {
        let hasAttachments = maildata.attachments && maildata.attachments.length;
        // false ha means no attachmens
        if (hasAttachments && !query.ha) {
            return false;
        }
        // true ha means attachmens must exist
        if (!hasAttachments && query.ha) {
            return false;
        }
    }

    // 3. 检查 message 大小
    if (query.size) {
        let messageSize = prepared.size;
        let filterSize = Math.abs(query.size);
        // negative value means "less than", positive means "more than"
        if (query.size < 0 && messageSize > filterSize) {
            return false;
        }
        if (query.size > 0 && messageSize < filterSize) {
            return false;
        }
    }

    // 4. 检查邮件文本
    if (
        query.text &&
        maildata.text
            .toLowerCase()
            .replace(/\s+/g, ' ')
            .indexOf(query.text.toLowerCase()) < 0
    ) {
        // message plaintext does not match the text field value
        return false;
    }

    log.silly('Filter', 'Filter %s matched message %s', filter.id, prepared.id);

    // we reached the end of the filter, so this means we have a match
    return filter;
}

module.exports = FilterHandler;

function parseReceived(str) {
    let result = new Map();

    str
        .trim()
        .replace(/[\r\n\s\t]+/g, ' ')
        .trim()
        .replace(/(^|\s+)(from|by|with|id|for)\s+([^\s]+)/gi, (m, p, k, v) => {
            let key = k.toLowerCase();
            let value = v;
            if (!result.has(key)) {
                result.set(key, value);
            }
        });

    let date = str
        .split(';')
        .pop()
        .trim();
    if (date) {
        date = new Date(date);
        if (date.getTime()) {
            result.set('date', date);
        }
    }

    return result;
}
