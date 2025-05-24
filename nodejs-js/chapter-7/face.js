const express = require("express");
const app = express();
app.use(express.static('frontend'));
app.use(express.json({ limit: '10mb' }));

const faceapi = require('@vladmandic/human');
 
 // Load models

//faceapi.nets.tinyFaceDetector.loadFromDisk('./model');
faceapi.nets.ssdMobilenetv1.loadFromDisk('./model')
.then(()=>{
  app.listen(8080, () => console.log('Server running on http://localhost:8080'));
});
//await faceapi.nets.faceRecognitionNet.loadFromDisk('./models');
//await faceapi.nets.faceLandmark68Net.loadFromDisk('./models');

const canvas = require('canvas');

const { Canvas, Image, ImageData } = canvas
faceapi.env.monkeyPatch({ Canvas, Image, ImageData })

 // Function to compare faces
async function compareFaces(image1Path, image2Path) {
  // Load images
  const image1 = await canvas.loadImage(image1Path);
  const image2 = await canvas.loadImage(image2Path);

  console.log("Loaded the images successfully");
 
  // Detect faces and compute descriptors
  const detection1 = await faceapi.detectSingleFace(image1).withFaceLandmarks().withFaceDescriptor();
  if (!detection1) {
    throw new Error("No faces detected in one or both images.");
  } else {
    console.log("Detected face image in both images.")
  }
  const detection2 = await faceapi.detectSingleFace(image2).withFaceLandmarks().withFaceDescriptor()
  if (!detection2) {
    throw new Error("No faces detected in one or both images.");
  } else {
    console.log("Detected face image in both images.")
  }
 
  // Calculate distance between descriptors
  const distance = faceapi.euclideanDistance(detection1.descriptor, detection2.descriptor);
 
  return distance;
}

app.post("/compare", (req, res) => {
  //const hlen = "data:image/png;base64,".length;
  const img1 = req.body.img1;
  const img2 = req.body.img2;

  compareFaces(img1, img2)
  .then(d => {
    res.json({"distance": d});
  })
  .catch(e => {
    console.error(e)
    res.status(500).json({"error": e.message})
  });
});
