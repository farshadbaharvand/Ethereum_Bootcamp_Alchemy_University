// SHA-256 Hashing Demo
// This demo shows how messages are converted to different formats and hashed
// using the SHA-256 algorithm commonly used in blockchain technology

const { sha256 } = require("ethereum-cryptography/sha256");
const { utf8ToBytes } = require("ethereum-cryptography/utils");
const readline = require('readline');

// Create interface for reading user input
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

// Function to convert a buffer to binary string
function bufferToBinary(buffer) {
    return Array.from(buffer)
        .map(byte => byte.toString(2).padStart(8, '0'))
        .join('');
}

// Function to convert a buffer to hex string
function bufferToHex(buffer) {
    return Array.from(buffer)
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
}

// Main function to demonstrate the hashing process
async function demonstrateHashing() {
    console.log("\n=== SHA-256 Hashing Demonstration ===\n");
    
    // Prompt user for input
    rl.question("Enter a message to hash: ", (message) => {
        console.log("\n=== Processing Your Message ===\n");
        
        // Step 1: Convert message to UTF-8 bytes
        console.log("Step 1: Converting message to UTF-8 bytes");
        const messageBytes = utf8ToBytes(message);
        console.log("UTF-8 bytes:", messageBytes);
        
        // Step 2: Show binary representation
        console.log("\nStep 2: Binary representation");
        const binaryString = bufferToBinary(messageBytes);
        console.log("Binary:", binaryString);
        
        // Step 3: Show hexadecimal representation
        console.log("\nStep 3: Hexadecimal representation");
        const hexString = bufferToHex(messageBytes);
        console.log("Hex:", hexString);
        
        // Step 4: Calculate SHA-256 hash
        console.log("\nStep 4: Calculating SHA-256 hash");
        const hash = sha256(messageBytes);
        console.log("SHA-256 Hash (hex):", bufferToHex(hash));
        
        // Educational note about SHA-256
        console.log("\n=== Educational Notes ===");
        console.log("- SHA-256 always produces a 256-bit (32-byte) hash");
        console.log("- The same input will always produce the same hash");
        console.log("- Even a small change in input produces a completely different hash");
        console.log("- It's practically impossible to derive the original message from the hash");
        
        rl.close();
    });
}

// Run the demonstration
demonstrateHashing();