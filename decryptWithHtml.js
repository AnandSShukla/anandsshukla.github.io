let AES_ENCRYPTION_IV ;
let rsaPvtKey ;

function getAesKey(xclientsign) {
  const privateKey = forge.pki.privateKeyFromPem(rsaPvtKey);
  const encryptedBytes = forge.util.decode64(xclientsign);
  const decryptedBytes = privateKey.decrypt(encryptedBytes, "RSA-OAEP", {
    md: forge.md.sha256.create(),
    mgf1: {
      md: forge.md.sha256.create(),
    },
  });
  const decryptedText = forge.util.decodeUtf8(decryptedBytes);
  const parts = decryptedText.split("::");
  return parts[0];
}

const unsafepayload = (payload) => {
  let base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) {
    base64 += "=";
  }
  return base64;
};

function base64ToBytes(base64Str) {
  return forge.util.decode64(base64Str);
}

function handleDecryption() {
  rsaPvtKey = document.getElementById("rsaPvtKey").value.trim();
  AES_ENCRYPTION_IV = document.getElementById("IV").value.trim();
  const xClientSignInput = document.getElementById("xClientSign").value.trim();
  let messageInput = document.getElementById("encryptedData").value.trim();
  const outputElement = document.getElementById("outputResult");

  if (!xClientSignInput || !messageInput) {
    outputElement.innerHTML = `<span class="error">Error: Please fill in both fields.</span>`;
    return;
  }
  if (!rsaPvtKey || !AES_ENCRYPTION_IV) {
    outputElement.innerHTML = `<span class="error">Error: Please fill Rsa Key and IV both fields.</span>`;
    return;
  }

  try {
    const req_Ky = getAesKey(xClientSignInput);
    const decipher = forge.cipher.createDecipher(
      "AES-CBC",
      forge.util.createBuffer(req_Ky, "utf8")
    );
    decipher.start({ iv: forge.util.createBuffer(AES_ENCRYPTION_IV, "utf8") });
    messageInput = unsafepayload(messageInput);
    const processedBytes = base64ToBytes(messageInput);
    decipher.update(forge.util.createBuffer(processedBytes));
    const success = decipher.finish();

    if (!success) {
      throw new Error(
        "Decryption operation failed. The key, IV, or payload might be incorrect."
      );
    }
    const processedMessage = decipher.output.toString("utf8");
    try {
      const jsonObject = JSON.parse(processedMessage);
      outputElement.innerText = JSON.stringify(jsonObject, null, 4);
    } catch (jsonErr) {
      outputElement.innerText = processedMessage;
    }
  } catch (error) {
    outputElement.innerHTML = `<span class="error">Decryption Error: ${error.message}</span>`;
    console.error(error);
  }
}
function copyToClipboard() {
  const outputText = document.getElementById("outputResult").innerText;
  const toast = document.getElementById("copyToast");

  // Prevent copying the placeholder text
  if (
    outputText === "Your decrypted output will appear here..." ||
    outputText.startsWith("Decryption Error:")
  ) {
    return;
  }

  navigator.clipboard
    .writeText(outputText)
    .then(() => {
      toast.style.display = "inline";
      setTimeout(() => {
        toast.style.display = "none";
      }, 2000);
    })
    .catch((err) => {
      alert("Failed to copy text: ", err);
    });
}
