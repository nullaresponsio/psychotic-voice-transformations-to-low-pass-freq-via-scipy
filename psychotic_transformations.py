#!/usr/bin/env python3
import argparse
import os
import io
import base64
import openai
import numpy as np
import scipy.signal
import soundfile as sf

FS_DEFAULT = 44100
PRESET_FS = [8000, 16000, 22050, 44100]

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

def parse_srt(path):
    subs = []
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read().strip().split('\n\n')
    for block in content:
        lines = block.splitlines()
        if len(lines) >= 3:
            subs.append(' '.join(lines[2:]))
    return subs

def main():
    parser = argparse.ArgumentParser(description="Process an SRT file into transformed speech audio")
    parser.add_argument('srt_file', help="Path to input .srt file")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--cutoff', type=float, help="Low-pass filter cutoff frequency in Hz")
    group.add_argument('--fs', type=int, choices=PRESET_FS, help="Output sampling frequency")
    parser.add_argument('--passthrough', action='store_true', help="Mix original and filtered audio")
    args = parser.parse_args()

    fs = args.fs if args.fs else FS_DEFAULT
    texts = parse_srt(args.srt_file)
    combined = np.array([], dtype=float)
    for text in texts:
        audio = synthesize_text(text, fs)
        if args.cutoff:
            audio = low_pass_filter(audio, fs, cutoff=args.cutoff)
        proc = psychotic_transform(audio, fs, passthrough=args.passthrough)
        combined = np.concatenate([combined, proc])
    out_path = os.path.splitext(args.srt_file)[0] + '_output.wav'
    sf.write(out_path, combined, fs)
    print(f"Written output to {out_path}")

if __name__ == '__main__':
    main()
