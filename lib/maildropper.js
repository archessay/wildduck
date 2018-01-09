'use strict';

const SeqIndex = require('seq-index');
const DkimStream = require('./dkim-stream');
const MessageSplitter = require('./message-splitter');
const seqIndex = new SeqIndex();
const GridFSBucket = require('mongodb').GridFSBucket;
const uuid = require('uuid');
const os = require('os');
const hostname = os.hostname().toLowerCase();
const addressparser = require('addressparser');
const punycode = require('punycode');
const tools = require('./tools');

class Maildropper {
    /**
     *  {
     *       db: db,// db = require('./lib/db');
     *       zone: config.sender.zone,// config = require('wild-config');
     *       collection: config.sender.collection,
     *       gfs: config.sender.gfs
     *   }
     * @param options
     */
    constructor(options) {
        this.options = options || {};
        this.db = options.db;
        this.zone = options.zone;
        this.collection = options.collection;
        this.gfs = options.gfs;

        this.gridstore =
            options.gridstore ||
            new GridFSBucket(this.db.senderDb, {// db.senderDb: wildduck
                bucketName: this.gfs// config.sender.gfs: mail
            });
    }

    /**
     *
     * @param options see 07OPTIONS.md for more details
     * @param callback callback for maildrop.push()
     * @returns {*}
     */
    push(options, callback) {

        // generate id, 用于拼接保存邮件body的文件名称：message id
        let id = options.id || seqIndex.get();
        let seq = 0;
        let documents = [];

        // new envelope
        let envelope = {
            id,

            from: options.from || '',
            to: Array.isArray(options.to) ? options.to : [].concat(options.to || []),

            interface: options.interface || 'maildrop',
            transtype: 'API',
            time: Date.now(),

            dkim: {
                hashAlgo: 'sha256'
            }
        };

        if (options.parentId) {
            envelope.parentId = options.parentId;
        }

        if (options.reason) {
            envelope.reason = options.reason;
        }

        let deliveries = [];

        if (options.targets) {
            options.targets.forEach(target => {
                switch (target.type) {
                    case 'mail':
                        deliveries.push({
                            to: target.value
                        });
                        break;

                    //    'relay' : property 'to' set to 'to'
                    case 'relay':
                        []
                            .concat(options.to || [])
                            .concat(target.recipient || [])
                            .forEach(to => {
                                let relayData = target.value;
                                if (typeof relayData === 'string') {
                                    relayData = tools.getRelayData(relayData);
                                }
                                deliveries.push({
                                    to,
                                    mx: relayData.mx,
                                    mxPort: relayData.mxPort,
                                    mxAuth: relayData.mxAuth,
                                    mxSecure: relayData.mxSecure,
                                    skipSRS: true
                                });
                            });
                        break;

                    //    'http' : property 'to' set to 'to'
                    case 'http':
                        []
                            .concat(options.to || [])
                            .concat(target.recipient || [])
                            .forEach(to => {
                                deliveries.push({
                                    to,
                                    http: true,
                                    targetUrl: target.value,
                                    skipSRS: true
                                });
                            });
                        break;
                }
            });
        }

        // If user does not have forwarding addresses set,
        // then forwarder is never invoked and this line is never reached.
        // https://github.com/nodemailer/wildduck/issues/50
        if (!deliveries.length) {// deliveries.length is Null
            deliveries = envelope.to.map(to => ({
                to
            }));
        }

        if (!deliveries.length) {
            let err = new Error('No valid recipients');
            err.code = 'ENORECIPIENTS';
            setImmediate(() => callback(err));
            return false;// 不返回stream
        }

        let messageSplitter = new MessageSplitter();
        let dkimStream = new DkimStream();

        // see 09ENVELOPE.json for more details
        messageSplitter.once('headers', headers => {
            envelope.headers = headers;
            this.updateHeaders(envelope);
        });
        // messageSplitter stream error, then pass it to dkimStream
        messageSplitter.once('error', err => dkimStream.emit('error', err));

        dkimStream.on('hash', bodyHash => {
            // store relaxed body hash for signing
            envelope.dkim.bodyHash = bodyHash;
            envelope.bodySize = dkimStream.byteLength;
        });

        this.store(id, dkimStream,
            err => {
            if (err) {// 写入失败
                return callback(err);
            }

            envelope.headers = envelope.headers.getList();

            this.setMeta(id, envelope, err => {
                if (err) {
                    return this.removeMessage(id, () => callback(err));
                }

                let date = new Date();

                for (let i = 0, len = deliveries.length; i < len; i++) {
                    let recipient = deliveries[i];

                    let deliveryZone = options.zone || this.zone || 'default';
                    let recipientDomain = recipient.to.substr(recipient.to.lastIndexOf('@') + 1).replace(/[[\]]/g, '');

                    seq++;

                    // 0x100: 256
                    // 0x10: 16
                    let deliverySeq = (seq < 0x100 ? '0' : '') + (seq < 0x10 ? '0' : '') + seq.toString(16);
                    let delivery = {
                        id,// envelope.id（用于拼接保存邮件body的文件名称：message id）
                        seq: deliverySeq,

                        // Actual delivery data
                        domain: recipientDomain,
                        sendingZone: deliveryZone,

                        assigned: 'no',

                        // actual recipient address
                        recipient: recipient.to,

                        locked: false,
                        lockTime: 0,

                        // earliest time to attempt delivery, defaults to now
                        queued: options.sendTime || date,

                        // queued date might change but created should not
                        created: date
                    };

                    // for http
                    if (recipient.http) {
                        delivery.http = recipient.http;
                        delivery.targetUrl = recipient.targetUrl;
                    }

                    // for relay
                    ['mx', 'mxPort', 'mxAuth', 'mxSecure'].forEach(key => {
                        if (recipient[key]) {
                            delivery[key] = recipient[key];
                        }
                    });

                    if (recipient.skipSRS) {
                        delivery.skipSRS = true;
                    }

                    documents.push(delivery);
                }

                // collection: config.sender.collection: "zone-queue"
                this.db.senderDb.collection(this.collection).insertMany(
                    documents,
                    {
                        w: 1,
                        ordered: false
                    },
                    err => {
                        if (err) {
                            return callback(err);
                        }

                        callback(null, envelope);
                    }
                );
            });
        });

        messageSplitter.pipe(dkimStream);
        return messageSplitter;
    }

    convertAddresses(addresses, withNames, addressList) {
        addressList = addressList || new Map();

        this.flatten(addresses || []).forEach(address => {
            if (address.address) {
                let normalized = this.normalizeAddress(address, withNames);
                let key = typeof normalized === 'string' ? normalized : normalized.address;
                addressList.set(key, normalized);
            } else if (address.group) {
                this.convertAddresses(address.group, withNames, addressList);
            }
        });

        return addressList;
    }

    parseAddressList(headers, key, withNames) {
        return this.parseAddressses(headers.getDecoded(key).map(header => header.value), withNames);
    }

    parseAddressses(headerList, withNames) {
        let map = this.convertAddresses(
            headerList.map(address => {
                if (typeof address === 'string') {
                    address = addressparser(address);
                }
                return address;
            }),
            withNames
        );
        return Array.from(map).map(entry => entry[1]);
    }

    normalizeDomain(domain) {
        domain = domain.toLowerCase().trim();
        try {
            domain = punycode.toASCII(domain);
        } catch (E) {
            // ignore
        }
        return domain;
    }

    // helper function to flatten arrays
    flatten(arr) {
        let flat = [].concat(...arr);
        return flat.some(Array.isArray) ? this.flatten(flat) : flat;
    }

    normalizeAddress(address, withNames) {
        if (typeof address === 'string') {
            address = {
                address
            };
        }
        if (!address || !address.address) {
            return '';
        }
        let user = address.address.substr(0, address.address.lastIndexOf('@'));
        let domain = address.address.substr(address.address.lastIndexOf('@') + 1);
        let addr = user.trim() + '@' + this.normalizeDomain(domain);

        if (withNames) {
            return {
                name: address.name || '',
                address: addr
            };
        }

        return addr;
    }

    updateHeaders(envelope) {
        // Fetch sender and receiver addresses
        envelope.parsedEnvelope = {
            from: this.parseAddressList(envelope.headers, 'from').shift() || false,
            to: this.parseAddressList(envelope.headers, 'to'),
            cc: this.parseAddressList(envelope.headers, 'cc'),
            bcc: this.parseAddressList(envelope.headers, 'bcc'),
            replyTo: this.parseAddressList(envelope.headers, 'reply-to').shift() || false,
            sender: this.parseAddressList(envelope.headers, 'sender').shift() || false
        };

        // Check Message-ID: value. Add if missing
        let mId = envelope.headers.getFirst('message-id');
        if (!mId) {
            mId = '<' + uuid.v4() + '@' + (envelope.from.substr(envelope.from.lastIndexOf('@') + 1) || hostname) + '>';

            envelope.headers.remove('message-id'); // in case there's an empty value
            envelope.headers.add('Message-ID', mId);
        }
        envelope.messageId = mId;

        // Check Date: value. Add if missing or invalid or future date
        let date = envelope.headers.getFirst('date');
        let dateVal = new Date(date);
        if (!date || dateVal.toString() === 'Invalid Date' || dateVal < new Date(1000)) {
            date = new Date().toUTCString().replace(/GMT/, '+0000');
            envelope.headers.remove('date'); // remove old empty or invalid values
            envelope.headers.add('Date', date);
        }

        envelope.date = date;

        // Remove BCC if present
        envelope.headers.remove('bcc');
    }

    /**
     * 保存邮件body。
     *      注意：这里将邮件 headers 和 body 分开存储，
     *      body 写入 grids，envelope 设置到 mail.files 的 metadata.data
     *
     * @param id envelope.id（用于拼接保存邮件body的文件名称：message id）
     * @param stream dkimStream
     * @param callback callback for store()
     */
    store(id, stream, callback) {
        let returned = false;// 用于标记stream的异步事件或store()方法是否已经执行callback返回
        let store = this.gridstore.openUploadStream('message ' + id, {
            fsync: true,
            contentType: 'message/rfc822',
            metadata: {
                created: new Date()
            }
        });

        // stream <=> dkimStream
        // dkimStream error
        stream.once('error', err => {
            if (returned) {// 如果stream的异步事件或store()方法已返回，则不做任何处理
                return;
            }
            returned = true;

            store.once('finish', () => {
                this.removeMessage(id, () => callback(err));
            });

            store.end();
        });

        store.once('error', err => {
            if (returned) {
                return;
            }
            returned = true;
            callback(err);
        });

        store.once('finish', () => {
            if (returned) {
                return;
            }
            returned = true;

            return callback(null);// 成功写入
        });

        // 将 chunks 写入mongo
        stream.pipe(store);
    }

    removeMessage(id, callback) {
        // Deletes all the chunks of this file in the database.
        this.gridstore.unlink('message ' + id, callback);
    }

    /**
     * 更新上一步保存的邮件body文件，为其设置 metadata.data
     *
     * @param id envelope.id（用于拼接保存邮件body的文件名称：message id）
     * @param data envelope
     * @param callback
     */
    setMeta(id, data, callback) {
        this.db.senderDb.collection(this.gfs + '.files').findOneAndUpdate(
            {
                filename: 'message ' + id
            },
            {
                $set: {
                    'metadata.data': data
                }
            },
            {},
            err => {
                if (err) {
                    return callback(err);
                }
                return callback();
            }
        );
    }
}

module.exports = Maildropper;
