'use strict';

/**
 *
 * @param options
 * @param callback callback for forwardMessage()
 */
module.exports = (options, callback) => {
    let mail = {
        parentId: options.parentId,
        reason: 'forward',

        from: options.sender,
        to: options.recipient,

        targets: options.targets,

        interface: 'forwarder'
    };

    // message stream <=> messageSplitter stream
    let message = options.maildrop.push(mail, (err, ...args) => {
        if (err || !args[0]) {
            if (err) {
                err.code = err.code || 'ERRCOMPOSE';
            }
            return callback(err, ...args);// 向 forwardMessage() 抛出错误
        }
        // 如果成功，插入一条messagelog
        options.db.database.collection('messagelog').insertOne(
            {
                id: args[0].id,// 用于拼接保存邮件body的文件名称：message id
                messageId: args[0].messageId,
                action: 'FORWARD',
                parentId: options.parentId,
                from: options.sender,
                to: options.recipient,
                targets: options.targets,
                created: new Date()
            },
            () => callback(err, args && args[0] && args[0].id)// 向 forwardMessage() 返回 envelope.id（用于拼接保存邮件body的文件名称：message id）
        );
    });
    if (message) {// message stream <=> messageSplitter stream
        if (options.stream) {
            options.stream.pipe(message);
            options.stream.once('error', err => {
                // messageSplitter stream error
                message.emit('error', err);
            });
            return;
        }

        setImmediate(() => {
            let pos = 0;
            let writeNextChunk = () => {
                if (pos >= options.chunks.length) {// index from 0
                    return message.end();
                }
                let chunk = options.chunks[pos++];
                if (!message.write(chunk)) {
                    /*
                        'drain' 事件：
                            新增于: v0.9.4
                            如果调用 stream.write(chunk) 方法返回 false，流将在适当的时机触发 'drain' 事件，这时才可以继续向流中写入数据。

                     */
                    return message.once('drain', writeNextChunk);
                } else {
                    setImmediate(writeNextChunk);
                }
            };
            setImmediate(writeNextChunk);
        });
    }
};
