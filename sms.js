const axios = require("axios");

async function sendSMS(numbers, message) {
  try {
    const response = await axios.post(
      "https://www.fast2sms.com/dev/bulkV2",
      {
        route: "q",
        message: message,
        numbers: numbers.join(",")
      },
      {
        headers: {
          authorization: process.env.b6AEgYvGf4OQ3lUDeJc20IBtP1LRmsFCkZHd87Wa9yMiNTxuXjkB4Z6xi0zuU7v1asKLJ9NbwOfIegGQ,
          "content-type": "application/json"
        }
      }
    );

    console.log("Fast2SMS response:", response.data);
    return response.data;
  } catch (error) {
    console.error("Fast2SMS error:", error.response?.data || error.message);
    throw error;
  }
}

module.exports = sendSMS;
