require('dotenv').config();
const { createServer } = require('http');
const express = require('express');
//const bodyParser = require('body-parser');
const { createEventAdapter } = require('@slack/events-api');
const { WebClient } = require('@slack/web-api');
const { strict } = require('assert');
const fetch = require('node-fetch');
//import JsFileDownloader from ('js-file-downloader');
const fs = require('fs');
const token = process.env.SLACK_TOKEN;
const web = new WebClient(token);
const slackSigningSecret = process.env.SLACK_SIGNING_SECRET;
const port = process.env.PORT || 3000;
const slackEvents = createEventAdapter(slackSigningSecret);

// Create an express application
const app = express();

// Plug the adapter in as a middleware
app.use('/slack/events', slackEvents.requestListener());

// BodyParser - deprecated, look for alternatives
// app.use(bodyParser());

// Receive and process file events here
slackEvents.on('file_created', async (event) => {
  console.log(`New file created: ID ${event.file_id}`);
  const file_id = event.file_id;
  console.log(`New file id variable: ${file_id}`);

  // use file ID to get additional file info 
  const res = await web.files.info({ file: file_id });

  // parse download URL from web.files.info response
  console.log(res)
  console.log('File info: ', res.file.url_private_download);
  const file_url = res.file.url_private_download
  const file_name = res.file.name;
  console.log(`New file URL variable: ${file_url}`);
  console.log(`New File Name: ${file_name}`);

  await downloadFile(file_url, `downloaded/${file_name}`, token)
  //const file = fs.readFileSync(`downloaded/${file_name}`);
  //console.log(file)
  // JsFileDownloader({ 
  //   url: file_url,
  //   headers: [
  //     { name: `Authorization', value: 'Bearer ${token}` }
  //   ]
  // })

});

const downloadFile = (async (url, path, token) => {
  const res = await fetch(url, {
    method: "GET",
    headers: {"Authorization": `Bearer ${token}`}

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
slackEvents.on('message', (event) => {
  if (event.text) {
    console.log(`Received a message event: user ${event.user} in channel ${event.channel} says ${event.text}`);
    const message_text = event.text;
    const message_user = event.user;
    const url_found = message_text.match(/((http|https|ftp|ftps)\:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}(\/\S*)?)/g);
    if (url_found === null) {
      console.log('URL Not Found');
    } else {
      console.log(`URL Found: ${url_found}`)
    }
  }
});

// Error Handling
slackEvents.on('error', console.error);

// Initialize a server for the express app - you can skip this and the rest if you prefer to use app.listen()
const server = createServer(app);
server.listen(port, () => {
  // Log a message when the server is ready
  console.log(`Listening for events on ${server.address().port} Slack signing secret: ${slackSigningSecret} Slack Token: ${token}`);
});