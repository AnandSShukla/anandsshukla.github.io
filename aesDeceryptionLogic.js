function onClickRadioSelection(value) {
  console.log(value);
  if (value === "rsa") {
    document.getElementsByClassName("containertwo")[0].style.display = "none";
    document.getElementsByClassName("container")[0].style.display = "block";
  } else {
    document.getElementsByClassName("containertwo")[0].style.display = "block";

    document.getElementsByClassName("container")[0].style.display = "none";
  }
}

function stringToBytes(value) {
    return new TextEncoder().encode(value);
}

function base64ToBytes(value) {
    value = value.replace(/\s/g, "");
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] =
            binary.charCodeAt(i);
    }
    return bytes;
}


async function decryptText(jsonMode) {
    const SECRET_KEY = document.getElementById("aesKey").value.trim();;
    const IV = document.getElementById("AESIV").value.trim();
    const input = document.getElementById("encryptedText");
    const output = document.getElementById("outputText");
    const status = document.getElementById("status");
    output.value = "";
    status.style.display = "none";


    try {
        const encryptedBase64 = input.value.trim();

        if (!encryptedBase64) {
            throw new Error(
                "Please enter the Base64 encrypted text."
            );
        }
        const encryptedBytes = base64ToBytes(encryptedBase64);

        const iv = stringToBytes(IV);

        if (iv.length !== 16) {
            throw new Error("IV must contain exactly 16 characters.");
        }

        let key = stringToBytes(SECRET_KEY);
        if (key.length !== 32) {
          throw new Error("Secret Key must contain exactly 32 characters.");
        }

        key = await crypto.subtle.importKey(
          "raw",
          key,
          {
            name: "AES-CBC",
          },
          false,
          ["decrypt"]
        );

        const decryptedBytes = await crypto.subtle.decrypt({
                    name: "AES-CBC",
                    iv: iv
                },
                key,
                encryptedBytes
            );


        const decryptedText = new TextDecoder("utf-8").decode(decryptedBytes);

        if (jsonMode) {
            let jsonData;
            try {
                jsonData = JSON.parse(decryptedText.trim());
            } catch (e) {
                output.value = decryptedText;                
                throw new Error("AES decryption succeeded, but the decrypted value is not valid JSON.");
            }
            output.value = JSON.stringify(jsonData,null,4);
        }
        else {
            output.value = decryptedText;
        }
        status.textContent = jsonMode ? "✓ JSON decrypted successfully." : "✓ Decryption successful.";
        status.className = "status success";
    } catch (error) {
        console.error(error);
        status.textContent = "✗ " + error.message;
        status.className = "status error";
    }
}

async function copyOutput() {
    const output =  document.getElementById("outputText");    
    if (!output.value) {
        return;
    }
    await navigator.clipboard.writeText(output.value);
    const status = document.getElementById("status");
    status.textContent = "✓ Output copied.";
    status.className = "status success";
}

