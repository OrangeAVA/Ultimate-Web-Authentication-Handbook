const express = require("express");
const app = express();
app.use(express.static('frontend'));
app.use(express.json({ limit: '10mb' }));

const tf = require('@tensorflow/tfjs-node');
const log = require('@vladmandic/pilogger');
const Human = require('@vladmandic/human');

let human = null;

const myConfig = {
  modelBasePath: 'file://node_modules/@vladmandic/human/models/',
  debug: true,
  face: { emotion: { enabled: false } },
  body: { enabled: false },
  hand: { enabled: false },
  gesture: { enabled: false },
};

async function init() {
  human = new Human.Human(myConfig);
  await human.tf.ready();
  log.info('Human:', human.version, 'TF:', tf.version_core);
  await human.load();
  log.info('Loaded:', human.models.loaded());
  log.info('Memory state:', human.tf.engine().memory());
}

const { dataUriToBuffer } = require('data-uri-to-buffer');

async function getDescriptors(imagedata){
  const decoded = dataUriToBuffer(imagedata);
  const buffer = new Uint8Array(decoded.buffer);
  const tensor = tf.node.decodeImage(buffer, 3);
  log.state('Loaded image size:', tensor.shape);
  const result = await human.detect(tensor, myConfig);
  tf.dispose(tensor);
  log.state('Detected faces:', result.face.length);
  return result;
}

async function compareFaces(imgdata1, imgdata2) {
  const res1 = await getDescriptors(imgdata1);
  const res2 = await getDescriptors(imgdata2);
  if (!res1 || !res1.face || res1.face.length === 0 || !res2 || !res2.face || res2.face.length === 0) {
    throw new Error('Could not detect face descriptors');
  }
  const similarity = human.match.similarity(res1.face[0].embedding, res2.face[0].embedding, { order: 2 });
  log.data('Similarity: ', similarity);
  return similarity;
}

app.post("/compare", (req, res) => {
  const img1 = req.body.img1;
  const img2 = req.body.img2;

  compareFaces(img1, img2)
  .then(d => {
    res.json({"similarity": d});
  })
  .catch(e => {
    console.error(e)
    res.status(500).json({"error": e.message})
  });
});

init()
.then(()=>{
  app.listen(8080, () => console.log('Server running on http://localhost:8080'));
}).catch(e =>{
  log.error("Unable to start the engine. Exiting...")
  process.exit(1);
})
