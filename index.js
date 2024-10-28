const { KmsKeyringNode, buildClient, CommitmentPolicy } = require('@aws-crypto/client-node');
const { KMSClient, DecryptCommand } = require('@aws-sdk/client-kms');
const { fromBase64 } = require('@aws-sdk/util-base64-node');
const { Twilio } = require('twilio');
const kmsClient = new KMSClient({ region: process.env.AWS_REGION });
const twilioClient = new Twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

const generatorKeyId = process.env.KEY_ALIAS;  // environment variable for alias of the key
const keyIds = [process.env.KEY_ARN];          // ARN of the key


const keyring = new KmsKeyringNode({ client: kmsClient, generatorKeyId, keyIds });
const { decrypt } = buildClient(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT);

const TWILIO_PHONE_NUMBER = process.env.TWILIO_PHONE_NUMBER;

const handler = async (event) => {
    try {
        // Extract encrypted code and recipient details from Cognito event
        const encryptedCode = event.request.code;
        const userPhone = event.request.userAttributes.phone_number;
        const deliveryType = event.request.clientMetadata.deliveryType; // 'sms' or 'voice'
        
        
        // Decode and decrypt the code using AWS KMS
        const decodedCode = fromBase64(encryptedCode);
        const decryptedCode = await decryptCode(decodedCode);

        // Construct the message to be sent
        const message = `Your verification code is: ${decryptedCode}`;
        console.log(message,"==============")
        // Check delivery type and send via Twilio SMS or voice call
        if (deliveryType === 'sms') {
            await sendSms(userPhone, message);
        } else if (deliveryType === 'voice') {
            await makeVoiceCall(userPhone, message);
        } else {
            throw new Error("Invalid delivery type. Must be 'sms' or 'voice'."+encryptedCode);
        }

        return event; // Return the event back to Cognito
    } catch (error) {
        console.error("Error in Lambda function:", error);
        throw new Error("Invalid delivery type. Must be 'sms' or 'voice'."+JSON.stringify(event.request)+"\n"+JSON.stringify(error));
    }
};

// Function to decrypt the code using KMS (AWS SDK v3)
async function decryptCode(ciphertext) {
    try {
        const { plaintext } = await decrypt(keyring, ciphertext);
        return plaintext.toString('utf-8'); // Convert Buffer to string if needed
    } catch (error) {
        console.error('Failed to decrypt code:', error);
        throw error;
    }
}

// Function to send SMS using Twilio
async function sendSms(to, message) {
    try {
        console.log(to,"----------------->",message)
        await twilioClient.messages.create({
            body: message,
            from: TWILIO_PHONE_NUMBER,
            to: to
        });
        console.log('SMS sent successfully');
    } catch (error) {
        console.error('Failed to send SMS:', error);
        throw error;
    }
}

// Function to make a voice call using Twilio
async function makeVoiceCall(to, message) {
    try {
        await twilioClient.calls.create({
            url: `http://twimlets.com/message?Message[0]=${encodeURIComponent(message)}`,
            to: to,
            from: TWILIO_PHONE_NUMBER
        });
        console.log('Voice call initiated successfully');
    } catch (error) {
        console.error('Failed to initiate voice call:', error);
        throw error;
    }
}

module.exports = { handler };
