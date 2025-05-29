import os
import io
import base64
import openai
import numpy as np
import scipy.signal
import soundfile as sf
from flask import Flask, Response, request
import threading

FS = 44100

def synthesize_text(text, fs):
    openai.api_key = os.getenv("OPENAI_API_KEY")
    resp = openai.audio.speech.create(model="tts-1", voice="alloy", input=text)
    audio_base64 = resp["audio"] if isinstance(resp["audio"], str) else resp["audio"]["data"]
    audio_bytes = base64.b64decode(audio_base64)
    data, sr = sf.read(io.BytesIO(audio_bytes))
    if data.ndim > 1:
        data = data[:, 0]
    return scipy.signal.resample(data, int(len(data) * fs / sr))

def low_pass_filter(audio, fs, cutoff=3000):
    b, a = scipy.signal.butter(4, cutoff/(fs/2), btype='low')
    return scipy.signal.lfilter(b, a, audio)

def psychotic_transform(audio, fs, passthrough=False):
    shifts = [0.8, 1.2, 0.6, 1.4, 0.9]
    layers = [scipy.signal.resample(audio, int(len(audio)/s))[:len(audio)] for s in shifts]
    echo = np.concatenate([audio, np.zeros(int(0.2*fs))])
    for i in range(3):
        echo = echo + np.pad(audio, (i*int(0.1*fs), 0))[:len(echo)]
    mix = sum(layers)/len(layers) + echo[:len(audio)]
    norm = mix / np.max(np.abs(mix))
    filtered = low_pass_filter(norm, fs)
    if passthrough:
        filtered = (filtered + audio) / 2
    return filtered

app = Flask(__name__)

@app.route('/audio', methods=['GET'])
def stream_tts():
    text = request.args.get('text', '')
    passthrough = request.args.get('passthrough', 'false').lower() == 'true'
    syn = synthesize_text(text, FS)
    proc = psychotic_transform(syn, FS, passthrough)
    buf = io.BytesIO()
    sf.write(buf, proc, FS, format='WAV')
    return Response(buf.getvalue(), mimetype='audio/wav')

@app.route('/process', methods=['POST'])
def stream_text():
    data = request.json or {}
    text = data.get('transcript', '')
    passthrough = data.get('passthrough', False)
    syn = synthesize_text(text, FS)
    proc = psychotic_transform(syn, FS, passthrough)
    buf = io.BytesIO()
    sf.write(buf, proc, FS, format='WAV')
    return Response(buf.getvalue(), mimetype='audio/wav')

if __name__ == '__main__':
    threading.Thread(target=lambda: app.run(host='0.0.0.0', port=8000)).start()
    print("Audio transform server running on http://0.0.0.0:8000")
