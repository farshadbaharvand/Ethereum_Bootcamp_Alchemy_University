// This code is used to encode a text message into a SHA256 hash.


import { sha256 } from "ethereum-cryptography/sha256.js";
import { utf8ToBytes, toHex } from "ethereum-cryptography/utils.js";
import readlineSync from 'readline-sync';

// Get input from user
const text = readlineSync.question('Enter your text: ');


// Convert text to UTF-8 bytes
const textBytes = utf8ToBytes(text);

// Calculate SHA256 hash
const hash = sha256(textBytes);

// Output results
console.log('\nResults:');
console.log('UTF-8 Bytes is :', textBytes);
console.log('Hex:', toHex(textBytes));
console.log('SHA256:', toHex(hash)); 
console.log('END OF CODE'); 