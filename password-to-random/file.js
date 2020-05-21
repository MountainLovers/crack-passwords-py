var fs = require('fs-extra');
var os = require('os');
var rl =  require('readline');

/**
 * 按行读写，无读取内容的处理，类似单纯的复制功能
 * @param {string} readName 
 * @param {string} writeName 
 */
var readWriteFileByLine = function(readName, writeName){
    var readStream =  fs.createReadStream(readName);
    var writeStream = fs.createWriteStream(writeName);
    var readLine = rl.createInterface({
        input: readStream,
        output: writeStream,
        terminal: true
    })
}

/**
 * 按行读写，中间包涵对读取的行内容的处理
 * @param {string} readName 
 * @param {string} writeName 
 * @param {Function} callback 
 */
var readWriteFileByLineWithProcess = function(readName,writeName,callback){
    var readStream = fs.createReadStream(readName);
    var writeStream = fs.createWriteStream(writeName);
    var readLine = rl.createInterface({
        input: readStream
    })
    readLine.on('line',function(line){
        var rs = callback(line);
        writeStream.write(rs + os.EOL);
    })
}

exports.readWriteFileByLine = readWriteFileByLine;
exports.readWriteFileByLineWithProcess = readWriteFileByLineWithProcess