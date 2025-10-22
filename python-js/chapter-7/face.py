# face.py - Flask API for face similarity comparison using face_recognition
#
# This file implements a Flask web server that provides an API endpoint to
# compare the similarity between two face images. It decodes base64-encoded
# images, extracts face embeddings using the face_recognition library, and
# computes the cosine similarity between the embeddings. The API returns a
# similarity score or an error if a face cannot be detected in either image.
#
# Functions:
#   decode_image(data_uri): Decodes a base64 data URI to a PIL Image.
#   get_face_embedding(image): Extracts a face embedding from a PIL Image.
#   compute_similarity(embedding1, embedding2): Computes cosine similarity
#     between two face embeddings.
#   serve_index(): Serves the frontend index.html file.
#   compare_faces(): API endpoint to compare two face images and return their
#     similarity score.

import base64
import io
from flask import Flask, request, jsonify, send_from_directory
from PIL import Image
import numpy as np
import face_recognition

app = Flask(__name__, static_folder='frontend')

def decode_image(data_uri):
  header, encoded = data_uri.split(',', 1)
  img_bytes = base64.b64decode(encoded)
  return Image.open(io.BytesIO(img_bytes))

def get_face_embedding(image):
  img_np = np.array(image)
  face_locations = face_recognition.face_locations(img_np)
  if not face_locations:
    return None
  encodings = face_recognition.face_encodings(img_np, face_locations)
  if not encodings:
    return None
  return encodings[0]

def compute_similarity(embedding1, embedding2):
  if embedding1 is None or embedding2 is None:
    return None
  norm1 = embedding1 / np.linalg.norm(embedding1)
  norm2 = embedding2 / np.linalg.norm(embedding2)
  similarity = np.dot(norm1, norm2)
  return float(similarity)

@app.route('/')
def serve_index():
  return send_from_directory(app.static_folder, 'index.html')

@app.route('/compare', methods=['POST'])
def compare_faces():
  data = request.get_json()
  img1_data = data.get('img1')
  img2_data = data.get('img2')
  if not img1_data or not img2_data:
    return jsonify({'error': 'Both image1 and image2 are required'}), 400

  try:
    img1 = decode_image(img1_data)
    img2 = decode_image(img2_data)
  except Exception as e:
    return jsonify({'error': f'Invalid image data: {str(e)}'}), 400

  embedding1 = get_face_embedding(img1)
  embedding2 = get_face_embedding(img2)

  if embedding1 is None or embedding2 is None:
    return jsonify({'error': 'Could not detect a face in one or both images'}), 400

  similarity = compute_similarity(embedding1, embedding2)
  return jsonify({'similarity': similarity})

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=8080)
