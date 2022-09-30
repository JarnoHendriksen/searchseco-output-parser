"use strict";
exports.__esModule = true;
var o2x = require("object-to-xml");
var input = "---------------\nHash 1234567890\n---------------\n\n  *Method methodName in file Test.cpp line 24\n   Authors of local function: \n  AuthorName\n  AuthorName2\n\nDATABASE\n  *Method functionName in project projName1 in file file.cpp line 33\n  URL: https://github.com/user/project\n  Method marked as vulnerable with code: 123(https://www.url-of-vulnerability.com)\n  Authors of function fuond in database: \n  \tAuthor1\n  \tAuthor2\n\n  *Method functionName in project projName2 in file file.cpp line 39\n  URL: https://github.com/user/project\n  Method marked as vulnerable with code: 123(https://www.url-of-vulnerability.com)\n  Authors of function fuond in database: \n  \tAuthor1\n  \tAuthor2\n\n---------------\nHash 9876544322\n---------------\n\n  *Method otherMethod in file OtherFile.cpp line 180\n   Authors of local function: \n  AuthorName\n\nDATABASE\n  *Method otherMethod in project projName1 in file file.cpp line 88\n  URL: https://github.com/user/project\n  Method marked as vulnerable with code: 123(https://www.url-of-vulnerability.com)\n  Authors of function fuond in database: \n  \tAuthor1\n  \tAuthor2";
var output = { methods: [] };
function ParseInput(input) {
    var hashIndices = getHashIndices(input);
    var ms = [];
    for (var i = 0; i < hashIndices.length - 1; i++) {
        var h = input[hashIndices[i]].split(' ')[1];
        var d = getMethodInfo(input, hashIndices[i], hashIndices[i + 1]);
        var m = getMatches(input, hashIndices[i], hashIndices[i + 1]);
        ms.push({ hash: h, data: d, matches: m });
    }
    return { methods: ms };
}
// Return list of indices of lines that contain a hash
// (i.e. they point to the start of a new hash)
function getHashIndices(input) {
    var indices = [];
    for (var i = 0; i < input.length; i++) {
        if (input[i].search('Hash') != -1)
            indices.push(i);
    }
    indices.push(input.length);
    return indices;
}
// Looks for the first line within a hash that contains '*Method', and extracts
// the data from the line.
// The line always looks like: *Method <methodName> in file <filename> line <lineNumber>,
// so the data are always the 2nd, 5th, and 7th words (index 1, 4, and 6 resp.)
function getMethodInfo(input, start, end) {
    var methodDataLine = getMatchIndicesOfHash(input, start, end);
    var words = input[methodDataLine[0]].split(' ').filter(function (x) { return x; });
    //console.log(words);
    var auth = [];
    // List of authors always starts two lines below the line with method data,
    // and ends before the line containing DATABASE
    var index = methodDataLine[0] + 2;
    while (input[index] != "DATABASE") {
        if (input[index] != "")
            auth.push(input[index]);
        index++;
    }
    var data = {
        name: words[1],
        file: words[4],
        line: parseInt(words[6]),
        authors: auth
    };
    return data;
}
function getMatches(input, start, end) {
    var matchList = [];
    var methodDataLine = getMatchIndicesOfHash(input, start, end);
    for (var i = 1; i < methodDataLine.length; i++) {
        var words = input[methodDataLine[i]].split(' ');
        var auth = [];
        var vulnLine = input[methodDataLine[i] + 2].split(' ')[6].split('(');
        //console.log(vulnLine + '|' + methodDataLine[i] + '|' + start + ',' + end);
        var vCode = vulnLine[0];
        var vUrl = vulnLine[1].substring(0, vulnLine[1].length - 1);
        var v = { code: vCode, url: vUrl };
        // List of authors always starts two lines below the line with method data,
        // and ends before the next *Method or the next Hash header (a string of dashes)
        var index = methodDataLine[i] + 4;
        while (input[index].search(/\*Method/) == -1 && input[index].search(/[-]+/) == -1 && input[index] != "" && index < end - 1) {
            auth.push(input[index++]);
        }
        var d = {
            name: words[1],
            file: words[7],
            project: words[4],
            line: parseInt(words[9]),
            authors: auth
        };
        var match = { data: d, vuln: v };
        matchList.push(match);
    }
    return matchList;
}
function getMatchIndicesOfHash(input, start, end) {
    var indices = [];
    for (var i = start; i < end; i++) {
        if (input[i].search(/\*Method/) != -1)
            indices.push(i);
    }
    return indices;
}
var inp = input.split('\n');
for (var n = 0; n < inp.length; n++) {
    inp[n] = inp[n].trim();
}
function printOutput(output) {
    console.log('--------------------------------------------------------------');
    for (var _i = 0, _a = output.methods; _i < _a.length; _i++) {
        var method = _a[_i];
        console.log('Hash: ' + method.hash);
        console.log('Name: ' + method.data.name);
        console.log('File: ' + method.data.file + ':' + method.data.line);
        console.log('Authors: ' + method.data.authors);
        console.log('-------');
        console.log('matches');
        console.log('-------');
        for (var _b = 0, _c = method.matches; _b < _c.length; _b++) {
            var match = _c[_b];
            console.log('Name: ' + match.data.name);
            console.log('Project: ' + match.data.project);
            console.log('File: ' + match.data.file + ':' + match.data.line);
            console.log('Vulnerabilities: ' + match.vuln.code + ' (' + match.vuln.url + ')');
            console.log('Authors: ' + match.data.authors + '\n');
        }
        console.log('--------------------------------------------------------------');
    }
}
output = ParseInput(inp);
switch (process.argv[2]) {
    case "-j":
    case "--json":
        console.log(JSON.stringify(output));
        break;
    case "-p":
    case "--pretty":
        printOutput(output);
        break;
    case "-x":
    case "--xml":
        console.log(o2x(output));
    case "-h":
    case "--help":
        console.log('Flags:');
        console.log('-j, --json     Return output in JSON format');
        console.log('-p, --pretty   Return pretty printed version of output');
        console.log('-x, --xml      Return output in XML format');
        break;
    default:
        console.log('Unknown flag. Using default printing method.');
        printOutput(output);
        break;
}
//console.log(JSON.stringify(output));
//printOutput(output);
