'use strict';

const log = require('npmlog');
const Transform = require('stream').Transform;
const Headers = require('mailsplit').Headers;

/**
 * MessageSplitter instance is a transform stream that separates message headers
 * from the rest of the body. Headers are emitted with the 'headers' event. Message
 * body is passed on as the resulting stream.
 */
class MessageSplitter extends Transform {
    constructor(options) {
        super(options);
        this.lastBytes = Buffer.alloc(4);
        this.headersParsed = false;
        this.headerBytes = 0;
        this.headerChunks = [];
        this.rawHeaders = false;
        this.bodySize = 0;
    }

    /**
     * Keeps count of the last 4 bytes in order to detect line breaks on chunk boundaries
     *
     * @param {Buffer} data Next data chunk from the stream
     */
    _updateLastBytes(data) {
        let lblen = this.lastBytes.length;// 4
        let nblen = Math.min(data.length, lblen);// 字节数组中用来作填充的长度

        // shift existing bytes
        // lblen: 字节数组的总长度(lblen = 4)
        // nblen: 字节数组中用来作填充的长度
        // len = lblen - nblen: 字节数组中需要保留的原字节数
        for (let i = 0, len = lblen - nblen; i < len; i++) {
            this.lastBytes[i] = this.lastBytes[i + nblen];
        }

        // add new bytes
        for (let i = 1; i <= nblen; i++) {
            this.lastBytes[lblen - i] = data[data.length - i];
        }
    }

    /**
     * Finds and removes message headers from the remaining body. We want to keep
     * headers separated until final delivery to be able to modify these
     *
     * @param {Buffer} data Next chunk of data
     * @return {Boolean} Returns true if headers are already found or false otherwise
     */
    _checkHeaders(data) {
        log.info("chunk：" + data.toString());

        // 已解析header，不再重复解析
        if (this.headersParsed) {
            return true;
        }

        // 分配4字节的buffer
        let lblen = this.lastBytes.length;
        let headerPos = 0;
        this.curLinePos = 0;

        // len = 4 + data.length
        for (let i = 0, len = this.lastBytes.length + data.length; i < len; i++) {
            let chr;
            if (i < lblen) {
                chr = this.lastBytes[i];
            } else {
                chr = data[i - lblen];
            }

            // 查找到空行分割的header
            // 回车 代码：CR ASCII码：\r ，十六进制，0x0d
            // 换行 代码：LF ASCII码：\n ，十六进制，0x0a
            if (chr === 0x0a && i) {// chr === `\n` && i >= 1
                let pr1 = i - 1 < lblen ? this.lastBytes[i - 1] : data[i - 1 - lblen];
                let pr2 = i > 1 ? (i - 2 < lblen ? this.lastBytes[i - 2] : data[i - 2 - lblen]) : false;
                if (pr1 === 0x0a) {// \n\n
                    this.headersParsed = true;
                    headerPos = i - lblen + 1;
                    this.headerBytes += headerPos;
                    break;
                } else if (pr1 === 0x0d && pr2 === 0x0a) {// \n\r\n
                    this.headersParsed = true;
                    headerPos = i - lblen + 1;
                    this.headerBytes += headerPos;
                    break;
                }
            }
        }

        if (this.headersParsed) {// can detect line breaks on chunk boundaries

            this.headerChunks.push(data.slice(0, headerPos));
            this.rawHeaders = Buffer.concat(this.headerChunks, this.headerBytes);

            this.headerChunks = null;

            this.headers = new Headers(this.rawHeaders);
            this.emit('headers', this.headers);

            if (data.length - 1 > headerPos) {
                // 获取后面的body
                let chunk = data.slice(headerPos);
                this.bodySize += chunk.length;
                // this would be the first chunk of data sent downstream
                // from now on we keep header and body separated until final delivery
                setImmediate(() => this.push(chunk));
            }
            return false;
        } else {// can not detect line breaks on chunk boundaries
            this.headerBytes += data.length;
            this.headerChunks.push(data);
        }

        // store last 4 bytes to catch header break
        this._updateLastBytes(data);

        return false;
    }

    /**
     * mail stream transport
     *
     * @param chunk mail chunk
     * @param encoding
     * @param callback
     * @returns {*}
     * @private
     */
    _transform(chunk, encoding, callback) {
        if (!chunk || !chunk.length) {// chunk is Null
            return callback();
        }

        if (typeof chunk === 'string') {
            chunk = new Buffer(chunk, encoding);
        }

        // 标记是否已解析出headers
        let headersFound;

        try {
            headersFound = this._checkHeaders(chunk);
        } catch (E) {
            return callback(E);
        }

        if (headersFound) {
            this.bodySize += chunk.length;
            this.push(chunk);
        }

        setImmediate(callback);
    }

    _flush(callback) {
        if (this.headerChunks) {
            // all chunks are checked but we did not find where the body starts
            // so emit all we got as headers and push empty line as body
            this.headersParsed = true;
            // add header terminator
            this.headerChunks.push(Buffer.from('\r\n\r\n'));
            this.headerBytes += 4;
            // join all chunks into a header block
            this.rawHeaders = Buffer.concat(this.headerChunks, this.headerBytes);

            this.headers = new Headers(this.rawHeaders);

            this.emit('headers', this.headers);
            this.headerChunks = null;

            // this is our body
            this.push(Buffer.from('\r\n'));
        }
        callback();
    }
}

module.exports = MessageSplitter;
