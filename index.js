var input = "---------------\nHash 1234567890\n---------------\n\n  *Method methodName in file Test.cpp line 24\n   Authors of local function: \n  AuthorName\n\nDATABASE\n  *Method functionName in project projName1 in file file.cpp line 33\n  URL: https://github.com/user/project\n  Method marked as vulnerable with code: 123(https://www.url-of-vulnerability.com)\n  Authors of function fuond in database: \n  \tAuthor1\n  \tAuthor2\n\n  *Method functionName in project projName2 in file file.cpp line 39\n  URL: https://github.com/user/project\n  Method marked as vulnerable with code: 123(https://www.url-of-vulnerability.com)\n  Authors of function fuond in database: \n  \tAuthor1\n  \tAuthor2\n\n---------------\nHash 9876544322\n---------------\n\n  *Method otherMethod in file OtherFile.cpp line 180\n   Authors of local function: \n  AuthorName\n\nDATABASE\n  *Method otherMethod in project projName1 in file file.cpp line 88\n  URL: https://github.com/user/project\n  Method marked as vulnerable with code: 123(https://www.url-of-vulnerability.com)\n  Authors of function fuond in database: \n  \tAuthor1\n  \tAuthor2";
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
    var words = input[methodDataLine[0]].split(' ');
    var auth = [];
    // List of authors always starts two lines below the line with method data,
    // and ends before the line containing DATABASE
    var index = methodDataLine[0] + 2;
    while (input[index] != "DATABASE") {
        auth.push(input[index++]);
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
        var vulnLine = input[methodDataLine[i] + 2].split(' ')[8].split('(');
        console.log(vulnLine + '|' + methodDataLine[i] + '|' + start + ',' + end);
        var vCode = vulnLine[0];
        var vUrl = vulnLine[1].substring(0, vulnLine[1].length - 1);
        var v = { code: vCode, url: vUrl };
        // List of authors always starts two lines below the line with method data,
        // and ends before the next *Method or the next Hash header (a string of dashes)
        var index = methodDataLine[i] + 4;
        while (input[index].search(/\*Method/) == -1 && input[index].search(/[-]+/) == -1 && index < end - 1) {
            console.log(index);
            auth.push(input[index++]);
        }
        var d = {
            name: words[1],
            file: words[4],
            line: parseInt(words[6]),
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
for (var _i = 0, inp_1 = inp; _i < inp_1.length; _i++) {
    var l = inp_1[_i];
    l.trim();
}
output = ParseInput(inp);
console.log(output.methods[0].hash);
