import o2x = require('object-to-xml');

let input = `---------------
Hash 1234567890
---------------

  *Method methodName in file Test.cpp line 24
   Authors of local function: 
  AuthorName
  AuthorName2

DATABASE
  *Method functionName in project projName1 in file file.cpp line 33
  URL: https://github.com/user/project
  Method marked as vulnerable with code: 123(https://www.url-of-vulnerability.com)
  Authors of function fuond in database: 
  	Author1
  	Author2

  *Method functionName in project projName2 in file file.cpp line 39
  URL: https://github.com/user/project
  Method marked as vulnerable with code: 123(https://www.url-of-vulnerability.com)
  Authors of function fuond in database: 
  	Author1
  	Author2

---------------
Hash 9876544322
---------------

  *Method otherMethod in file OtherFile.cpp line 180
   Authors of local function: 
  AuthorName

DATABASE
  *Method otherMethod in project projName1 in file file.cpp line 88
  URL: https://github.com/user/project
  Method marked as vulnerable with code: 123(https://www.url-of-vulnerability.com)
  Authors of function fuond in database: 
  	Author1
  	Author2`;


interface Output{
  methods : Method[]
}

interface Method{
  hash : String,
  data : MethodData,
  matches : Match[]
}

interface MethodData{
  name : String,
  project? : String,
  file : String,
  line : number,
  authors : String[],
}

interface Match{
  data : MethodData,
  vuln : Vuln,
}

interface Vuln{
  code : String,
  url : String
}

let output : Output = {methods: []};

function ParseInput(input : String[]) : Output{
  let hashIndices : number[] = getHashIndices(input);
  let ms : Method[] = [];
  
  for (let i = 0; i < hashIndices.length - 1; i++){
    let h = input[hashIndices[i]].split(' ')[1];
    let d = getMethodInfo(input, hashIndices[i], hashIndices[i+1]);
    let m = getMatches(input, hashIndices[i], hashIndices[i+1]);
    ms.push({hash: h, data: d, matches: m});
  }

  return {methods: ms}
}


// Return list of indices of lines that contain a hash
// (i.e. they point to the start of a new hash)
function getHashIndices(input : String[]) : number[]{
  let indices : number[] = [];

  for (let i = 0; i < input.length; i++){
    if (input[i].search('Hash') != -1) indices.push(i);
  }

  indices.push(input.length);

  return indices;
}

// Looks for the first line within a hash that contains '*Method', and extracts
// the data from the line.
// The line always looks like: *Method <methodName> in file <filename> line <lineNumber>,
// so the data are always the 2nd, 5th, and 7th words (index 1, 4, and 6 resp.)
function getMethodInfo(input : String[], start : number, end : number) : MethodData{
  let methodDataLine = getMatchIndicesOfHash(input, start, end);
  let words = input[methodDataLine[0]].split(' ').filter(x => x);
  //console.log(words);
  let auth : String[] = [];

  // List of authors always starts two lines below the line with method data,
  // and ends before the line containing DATABASE
  let index = methodDataLine[0] + 2;
  while (input[index] != "DATABASE"){
    if (input[index] != "") auth.push(input[index]);
    index++;
  }

  let data : MethodData = {
    name: words[1],
    file: words[4],
    line: parseInt(words[6]),
    authors: auth
  };
  return data;
}

function getMatches(input : String[], start : number, end : number) : Match[]{
  let matchList : Match[] = [];
  let methodDataLine = getMatchIndicesOfHash(input, start, end);
  for (let i = 1; i < methodDataLine.length; i++){
    let words = input[methodDataLine[i]].split(' ');
    let auth : String[] = [];

    let vulnLine = input[methodDataLine[i]+2].split(' ')[6].split('(');
    //console.log(vulnLine + '|' + methodDataLine[i] + '|' + start + ',' + end);
    let vCode = vulnLine[0];
    let vUrl = vulnLine[1].substring(0, vulnLine[1].length - 1);

    let v : Vuln = {code: vCode, url: vUrl};

    // List of authors always starts two lines below the line with method data,
    // and ends before the next *Method or the next Hash header (a string of dashes)
    let index = methodDataLine[i] + 4;
    while (input[index].search(/\*Method/) == -1 && input[index].search(/[-]+/) == -1 && input[index]!="" && index < end-1){
      auth.push(input[index++]);
    }

    let d : MethodData = {
      name: words[1],
      file: words[7],
      project: words[4],
      line: parseInt(words[9]),
      authors: auth
    };

    let match : Match = {data: d, vuln: v};

    matchList.push(match);
  }

  return matchList;
}

function getMatchIndicesOfHash(input : String[], start : number, end : number){
  let indices : number[] = [];
  for(let i = start; i < end; i++){
    if(input[i].search(/\*Method/) != -1) indices.push(i);
  }

  return indices;
}

let inp = input.split('\n');
for(let n = 0; n < inp.length; n++){
  inp[n] = inp[n].trim();
}

function printOutput(output : Output){
  console.log('--------------------------------------------------------------');
  for (const method of output.methods){
    console.log('Hash: ' + method.hash);
    console.log('Name: ' + method.data.name);
    console.log('File: ' + method.data.file + ':' + method.data.line);
    console.log('Authors: ' + method.data.authors);
    console.log('-------');
    console.log('matches');
    console.log('-------');
    for (const match of method.matches){
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

switch (process.argv[2]){
  case "-j": case"--json":
    console.log(JSON.stringify(output));
    break;
  case "-p": case "--pretty":
    printOutput(output);
    break;
  case "-x": case "--xml":
    console.log(o2x(output));
  case "-h": case "--help":
    console.log('Flags:');
    console.log('-j, --json     Return output in JSON format');
    console.log('-p, --pretty   Return pretty printed version of output');
    console.log('-x, --xml      Return output in XML format');
    break;
  default:
    console.log('Unknown flag. Using default printing method.')
    printOutput(output);
    break;
}

//console.log(JSON.stringify(output));
//printOutput(output);