'use strict';

// Simple LMTP server that accepts all messages for valid recipients

const config = require('wild-config');
const log = require('npmlog');
const ObjectID = require('mongodb').ObjectID;
const SMTPServer = require('smtp-server').SMTPServer;
const tools = require('./lib/tools');
const MessageHandler = require('./lib/message-handler');
const UserHandler = require('./lib/user-handler');
const FilterHandler = require('./lib/filter-handler');
const db = require('./lib/db');
const certs = require('./lib/certs');

let messageHandler;
let userHandler;
let filterHandler;
let spamChecks, spamHeaderKeys;

config.on('reload', () => {
    spamChecks = tools.prepareSpamChecks(config.spamHeader);
    spamHeaderKeys = spamChecks.map(check => check.key);

    if (filterHandler) {
        filterHandler.spamChecks = spamChecks;
        filterHandler.spamHeaderKeys = spamHeaderKeys;
    }

    log.info('LMTP', 'Configuration reloaded');
});

const serverOptions = {
    lmtp: true,

    secure: config.lmtp.secure,
    secured: config.lmtp.secured,

    // log to console
    logger: {
        info(...args) {
            args.shift();
            log.info('LMTP', ...args);
        },
        debug(...args) {
            args.shift();
            log.silly('LMTP', ...args);
        },
        error(...args) {
            args.shift();
            log.error('LMTP', ...args);
        }
    },

    name: config.lmtp.name || false,

    // not required but nice-to-have
    banner: config.lmtp.banner || 'Welcome to WildDuck Mail Server',

    disabledCommands: ['AUTH'].concat(config.lmtp.disableSTARTTLS ? 'STARTTLS' : []),

    onMailFrom(address, session, callback) {
        // reset session entries
        session.users = [];

        // accept alls sender addresses
        return callback();
    },

    // Validate RCPT TO envelope address. Example allows all addresses that do not start with 'deny'
    // If this method is not set, all addresses are allowed
    onRcptTo(rcpt, session, callback) {
        let originalRecipient = tools.normalizeAddress(rcpt.address);
        userHandler.get(
            originalRecipient,
            {
                name: true,
                forwards: true,
                forward: true,
                targetUrl: true,
                autoreply: true,
                encryptMessages: true,
                encryptForwarded: true,
                pubKey: true
            },
            (err, userData) => {
                if (err) {
                    log.error('LMTP', err);
                    return callback(new Error('Database error'));
                }
                if (!userData) {
                    return callback(new Error('Unknown recipient'));
                }

                if (!session.users) {
                    session.users = [];
                }

                session.users.push({
                    recipient: originalRecipient,
                    user: userData
                });

                callback();
            }
        );
    },

    /**
     * Handle message stream
     *
     * For DATA commond of lmtp
     *
     * @param stream message stream, 邮件消息体
     * @param session see 01SESSION.json for more details
     * @param callback 回调
     */
    onData(stream, session, callback) {
        let chunks = [];
        let chunklen = 0;

        /*
            读取邮件消息体。

            'readable' 事件：
                'readable' 事件将在流中有数据可供读取时触发。
                在某些情况下，为 'readable' 事件添加回调将会导致一些数据被读取到内部缓存中。

                当到达流数据尾部时， 'readable' 事件也会触发。触发顺序在 'end' 事件之前。

                事实上， 'readable' 事件表明流有了新的动态：要么是有了新的数据，要么是到了流的尾部。
                对于前者， stream.read() 将返回可用的数据。而对于后者， stream.read() 将返回 null。

         */
        stream.on('readable', () => {
            let chunk;
            while ((chunk = stream.read()) !== null) {
                chunks.push(chunk);
                chunklen += chunk.length;
            }
        });

        stream.once('error', err => {// error
            log.error('LMTP', err);
            callback(new Error('Error reading from stream'));
        });

        stream.once('end', () => {
            // sender, eg, example@exam.ple44
            let sender = tools.normalizeAddress((session.envelope.mailFrom && session.envelope.mailFrom.address) || '');

            let responses = [];
            let users = session.users;
            let stored = 0;

            let transactionId = new ObjectID();
            let prepared = false;

            let storeNext = () => {
                // all users (recipients) has processed
                if (stored >= users.length) {
                    return callback(null, responses.map(r => r.response));
                }

                let rcptData = users[stored++];
                let recipient = rcptData.recipient;// 收件人邮箱
                let userData = rcptData.user;// 收件人user信息

                let response = responses.filter(r => r.userData === userData);
                if (response.length) {// 如果是同一收件人，直接返回之前的响应
                    responses.push(response[0]);
                    return storeNext();
                }

                filterHandler.process(
                    {
                        mimeTree: prepared && prepared.mimeTree,
                        maildata: prepared && prepared.maildata,
                        user: userData,// 收件人user信息
                        sender,
                        recipient,// 收件人邮箱
                        chunks,
                        chunklen,
                        meta: {
                            transactionId,
                            source: 'MX',
                            from: sender,
                            to: [recipient],
                            origin: session.remoteAddress,
                            originhost: session.clientHostname,
                            transhost: session.hostNameAppearsAs,
                            transtype: session.transmissionType,
                            time: new Date()
                        }
                    },
                    (err, response, preparedResponse) => {
                        if (err) {
                            //
                        }

                        if (response) {
                            responses.push(response);
                        }

                        if (!prepared && preparedResponse) {
                            prepared = preparedResponse;
                        }

                        setImmediate(storeNext);
                    }
                );
            };

            //
            storeNext();
        });
    }
};

certs.loadTLSOptions(serverOptions, 'lmtp');

const server = new SMTPServer(serverOptions);

certs.registerReload(server, 'lmtp');

module.exports = done => {
    if (!config.lmtp.enabled) {
        return setImmediate(() => done(null, false));
    }

    spamChecks = tools.prepareSpamChecks(config.spamHeader);
    spamHeaderKeys = spamChecks.map(check => check.key);

    messageHandler = new MessageHandler({
        database: db.database,
        users: db.users,
        redis: db.redis,
        gridfs: db.gridfs,
        attachments: config.attachments
    });

    userHandler = new UserHandler({
        database: db.database,
        users: db.users,
        redis: db.redis,
        authlogExpireDays: config.log.authlogExpireDays
    });

    filterHandler = new FilterHandler({
        db,// db = require('./lib/db');
        sender: config.sender,// config = require('wild-config');
        messageHandler,
        spamHeaderKeys,
        spamChecks
    });

    let started = false;

    server.on('error', err => {
        if (!started) {
            started = true;
            return done(err);
        }
        log.error('LMTP', err);
    });

    server.listen(config.lmtp.port, config.lmtp.host, () => {
        if (started) {
            return server.close();
        }
        started = true;
        done(null, server);
    });
};
