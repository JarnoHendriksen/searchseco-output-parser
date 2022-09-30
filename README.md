## How to run
First, compile the Typescript file to JavaScript:\
`tsc index.ts`\
Then, run the program using node. You can choose the type of output by adding a flag (listed below):\
`node index.js [output-flag]`

### Output types
 - JSON: add `-j` or `--json` to get the output in JSON format
 - XML: add `-x` or `--xml` to get an XML output
 Leaving out the output flag simply pretty-prints the contents of the JS object, which can be useful for debugging.

## Input
Currently, the input is simply hard-coded, because SearchSECO is broken. Eventually, a Github Action is supposed to feed the output of SearchSECO to this parser.