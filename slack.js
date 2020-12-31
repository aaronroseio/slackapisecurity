require('dotenv').config();
const { createServer } = require('http');
const express = require('express');
const { createEventAdapter } = require('@slack/events-api');
const { WebClient } = require('@slack/web-api');
const { strict } = require('assert');
const fetch = require('node-fetch');
const fs = require('fs');
const md5File = require('md5-file');
const md5 = require('md5');
const token = process.env.SLACK_TOKEN;
const cpRepKey = process.env.CP_REP_API;
const cpRepToken = process.env.CP_REP_TOKEN;
const cpTpKey = process.env.CP_TE_API_TOKEN;
const web = new WebClient(token);
const slackSigningSecret = process.env.SLACK_SIGNING_SECRET;
const port = process.env.PORT || 3000;
const slackEvents = createEventAdapter(slackSigningSecret);
const FormData = require('form-data');
const { response } = require('express');
const sleep = (milliseconds) => {
  return new Promise(resolve => setTimeout(resolve, milliseconds))
}

// Create an express application
const app = express();

// Plug the adapter in as a middleware
app.use('/slack/events', slackEvents.requestListener());

// Receive and process file events here
slackEvents.on('file_shared', async (event) => {
  console.log(`New file created: ID ${event.file_id}`);
  const file_id = event.file_id;
  console.log(`New file id variable: ${file_id}`);

  // use file ID to get additional file info 
  const res = await web.files.info({ file: file_id });

  // parse download URL from web.files.info response
  //console.log(res)
  //console.log('File info: ', res.file.url_private_download);
  const file_url = res.file.url_private_download
  const file_name = res.file.name;
  console.log(`New file URL variable: ${file_url}`);
  console.log(`New File Name: ${file_name}`);
  const file_path = `downloaded/${file_name}`
  await downloadFile(file_url, file_path, token);
  const hashFile = md5File.sync(file_path)
  console.log(`new hashfile variable = ${hashFile}`)
  const md5Res = await fileQuery(hashFile, cpTpKey)
  //console.log(`md5 query response is:`, md5Res.response[0])
  if (md5Res.response[0].status.code = 1004) {
    console.log("Uploading File for analysis")
    const fileUpRes = await fileUpload(hashFile, cpTpKey, file_path, file_name)
    //console.log('Upload response:', fileUpRes)
    const continueQuery = await continuousFileQuery(hashFile, cpTpKey)
    //console.log(continueQuery)
    if (continueQuery.response[0].te.combined_verdict = "benign") { //This function will try every 30 seconds for a TE verdict
      console.log("it's safe from continuous")
    } else if (continueQuery.response[0].te.combined_verdict = "malicious") { //This function will try every 30 seconds for a TE verdict
      console.log("deleting malicious file from continuous")
      const fileDelete = await web.files.delete({ file: file_id });
      await web.chat.postMessage({ channel: event.channel, text: `The file you shared in your message was found to be malicious & has been deleted.` })
      console.log(fileDelete)
    }
  } else if (md5Res.response[0].te.combined_verdict = "malicious") {
    console.log("deleting malcious file...")
    const fileDelete = await web.files.delete({ file: file_id });
    await web.chat.postMessage({ channel: event.channel, text: `The file you shared in your message was found to be malicious & has been deleted.` })
    console.log(fileDelete)
  } else if (md5Res.response[0].te.combined_verdict = "benign") {
    console.log("it's safe from initial query, no upload needed")
  }
});
const downloadFile = (async (url, path, token) => {
  const res = await fetch(url, {
    method: "GET",
    headers: { "Authorization": `Bearer ${token}` }

  })
  const fileStream = fs.createWriteStream(path);
  await new Promise((resolve, reject) => {
    res.body.pipe(fileStream);
    res.body.on("error", reject);
    fileStream.on("finish", resolve);
  });
  console.log(`finished downloading`)
});


// Receive messages here
slackEvents.on('message', async (event) => {
  if (event.text) {
    //console.log(`Received a message event: user ${event.user} in channel ${event.channel} says ${event.text}`);
    const message_text = event.text;
    const message_user = event.user;
    const url_found = message_text.match(/((http|https|ftp|ftps)\:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}(\/\S*)?)/g);
    if (url_found === null) {
      console.log('URL Not Found');
    } else {
      console.log(`URL Found`, 'hi', url_found[0])
      const res = await urlQuery(url_found, cpRepKey, cpRepToken)
      console.log(`Query Response is:`, res.response[0])
      console.log(`URL Risk is:`, res.response[0].risk)
      if (res.response[0].risk > 10) {
        try {
          await web.chat.delete({ channel: event.channel, ts: event.ts });
          await web.chat.postMessage({ channel: event.channel, text: `The URL you shared in your message was found to be malicious, thus the message has been deleted.` });
        }
        catch (error) {
          console.error(error);
        }
      }
    }
  }
});

//CP File Query Function
const fileQuery = (async (md5Value, cpTpKey) => {
  const body = JSON.stringify({ "request": [{ "md5": md5Value }] })
  //console.log(`query body is ${body}`)
  const res = await fetch(`https://te.checkpoint.com/tecloud/api/v1/file/query`, {
    method: "POST",
    body: body,
    headers: { 'Authorization': cpTpKey, 'Content-Type': 'application/json', 'Content-Length': body.length.toString() }

  })
  return await res.json()
});

//CP File Upload Function
const fileUpload = (async (md5Value, cpTpKey, file_path, file_name) => {
  let readStream = fs.createReadStream(file_path)
  const formdata = new FormData();
  formdata.append("request", "{\"request\" :{ \"features\":[ \"te\"],\"te\": {\"reports\": [\"xml\", \"pdf\"]}}}");
  formdata.append("file", readStream);

  const headers = { 'Authorization': cpTpKey, ...formdata.getHeaders() }

  const res = await fetch(`https://te.checkpoint.com/tecloud/api/v1/file/upload`, {
    method: "POST",
    body: formdata,
    headers: headers

  })
  return await res.json()
});

//Continuous File Upload Query
const continuousFileQuery = async (md5Value, cpTpKey) => {
  let uploadQueryResponse = await fileQuery(md5Value, cpTpKey)
  while (uploadQueryResponse.response[0].te.status.label = "PENDING") {
    await sleep(30000)
    console.log("trying again")
    //console.log(uploadQueryResponse.response[0].te.status.label)
    uploadQueryResponse = await fileQuery(md5Value, cpTpKey)
    //console.log(uploadQueryResponse)
    if (uploadQueryResponse.response[0].te.status.label !== "PENDING") {
      console.log("successfully processed file, returning verdict")
      //console.log(uploadQueryResponse.response[0].te.status.label)
      return uploadQueryResponse
    }
  }
}


//CP URL Query Function
const urlQuery = (async (url_found, cpRepKey, cpRepToken) => {
  const body = JSON.stringify({
    "request": [{
      "resource": url_found[0]
    }]
  })
  //console.log(`body is ${body}`)
  const res = await fetch(`https://rep.checkpoint.com/url-rep/service/v2.0/query?resource=${url_found[0]}`, {
    method: "POST",
    body: body,
    headers: { "Client-Key": cpRepKey, "token": cpRepToken, 'Content-Type': 'application/json' }

  })
  return await res.json()
});

//DLP Function -- future 


// Slack Error Handling
slackEvents.on('error', console.error);

// Initialize a server for the express app 
const server = createServer(app);
server.listen(port, () => {
  // Log a message when the server is ready
  console.log(`Listening for events on ${server.address().port} Slack signing secret: ${slackSigningSecret} Slack Token: ${token}`);
});
// use these for debugging fetch
// console.log(res.ok);
// console.log(res.status);
// console.log(res.statusText);
// console.log(res.headers.raw());
// console.log(res.headers.get('content-type'));
// console.log(res.status, res.statusText, res.response, res.text)
