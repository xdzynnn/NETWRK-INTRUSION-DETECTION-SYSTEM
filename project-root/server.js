require('dotenv').config(); // Load environment variables from the .env file

const express = require('express');
const fs = require('fs-extra');
const crypto = require('crypto');
const openpgp = require('openpgp');
const tar = require('tar');

const passphrase = process.env.PRIVATE_KEY_PASSPHRASE; // Access the passphrase environment variable

const app = express();
const port = 3000;

// Middleware for parsing JSON requests
app.use(express.json());

// Generate Log
app.post('/generate-log', (req, res) => {
  try {
    const logData = 'Sample log data';
    const logPath = './logs.txt';

    console.log('Generating log...');
    fs.outputFileSync(logPath, logData);

    const hash = crypto.createHash('sha256').update(logData).digest('hex');
    fs.outputFileSync('./logs.hash', hash);

    console.log('Log generated and hash created.');
    res.send('Log generated and hash created.');
  } catch (err) {
    console.error('Error generating log:', err);
    res.status(500).send(`Error generating log: ${err.message}`);
  }
});

// Sign Log
app.post('/sign-log', async (req, res) => {
  try {
    console.log('Signing log...');
    const privateKeyArmored = fs.readFileSync('privateKey.asc', 'utf8');
    console.log('Private Key Loaded.');

    const privateKey = await openpgp.readPrivateKey({ armoredKey: privateKeyArmored });
    const decryptedPrivateKey = await openpgp.decryptKey({ privateKey, passphrase });
    console.log('Private Key Decrypted.');

    const message = await openpgp.createMessage({ text: fs.readFileSync('./logs.txt', 'utf8') });
    const detachedSignature = await openpgp.sign({
      message,
      signingKeys: decryptedPrivateKey,
      detached: true
    });

    fs.outputFileSync('./logs.sig', detachedSignature);
    console.log('Log signed successfully.');
    res.send('Log signed successfully.');
  } catch (err) {
    console.error('Error signing log:', err);
    res.status(500).send(`Error signing log: ${err.message}`);
  }
});

// Encrypt Log
app.post('/encrypt-log', async (req, res) => {
  try {
    console.log('Encrypting log...');
    const publicKeyArmored = fs.readFileSync('publicKey.asc', 'utf8');
    console.log('Public Key Loaded.');

    const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });
    const message = await openpgp.createMessage({ text: fs.readFileSync('./logs.txt', 'utf8') });
    const encrypted = await openpgp.encrypt({
      message,
      encryptionKeys: publicKey
    });

    fs.outputFileSync('./logs.gpg', encrypted);
    console.log('Log encrypted successfully.');
    res.send('Log encrypted successfully.');
  } catch (err) {
    console.error('Error encrypting log:', err);
    res.status(500).send(`Error encrypting log: ${err.message}`);
  }
});

// Create Archive
app.post('/create-archive', async (req, res) => {
  try {
    console.log('Creating archive...');
    const filesToArchive = ['./logs.txt', './logs.sig', './logs.gpg'];
    console.log('Files to Archive:', filesToArchive);

    await tar.c(
      {
        gzip: true,
        file: './logs.tar.gz'
      },
      filesToArchive
    );

    const fileBuffer = fs.readFileSync('./logs.tar.gz');
    const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
    fs.outputFileSync('./logs.tar.gz.hash', hash);

    console.log('Archive created and hash generated.');
    res.send('Archive created and hash generated.');
  } catch (err) {
    console.error('Error creating archive:', err);
    res.status(500).send(`Error creating archive: ${err.message}`);
  }
});

// Serve static files from the "public" directory
app.use(express.static('public'));

// Serve the frontend HTML
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

// Start the server
app.listen(port, () => {
  console.log(`NIDS backend server is running at http://localhost:${port}`);
});