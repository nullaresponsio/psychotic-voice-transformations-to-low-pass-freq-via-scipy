O3 o4-mini-high o4 etc training and gen multi modal

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader

class LoRAAdapter(nn.Module):
    def __init__(self, dim, rank=4):
        super().__init__()
        self.down = nn.Linear(dim, rank, bias=False)
        self.up = nn.Linear(rank, dim, bias=False)
    def forward(self, x):
        return self.up(self.down(x))

class TransformerBlock(nn.Module):
    def __init__(self, dim, heads=8, use_lora=False, lora_rank=4):
        super().__init__()
        self.attn = nn.MultiheadAttention(dim, heads)
        self.use_lora = use_lora
        if use_lora:
            self.lora_q = LoRAAdapter(dim, lora_rank)
            self.lora_k = LoRAAdapter(dim, lora_rank)
            self.lora_v = LoRAAdapter(dim, lora_rank)
        self.ff = nn.Sequential(
            nn.Linear(dim, dim*4),
            nn.GELU(),
            nn.Linear(dim*4, dim)
        )
        self.norm1 = nn.LayerNorm(dim)
        self.norm2 = nn.LayerNorm(dim)
    def forward(self, x):
        q = k = v = x
        if self.use_lora:
            q = q + self.lora_q(x)
            k = k + self.lora_k(x)
            v = v + self.lora_v(x)
        attn_out, _ = self.attn(q, k, v)
        x = x + attn_out
        x = self.norm1(x)
        x = x + self.ff(x)
        return self.norm2(x)

class Encoder(nn.Module):
    def __init__(self, vocab_size, dim, layers, use_lora, lora_rank):
        super().__init__()
        self.embed = nn.Embedding(vocab_size, dim)
        self.blocks = nn.ModuleList([
            TransformerBlock(dim, use_lora=use_lora, lora_rank=lora_rank)
            for _ in range(layers)
        ])
    def forward(self, tokens):
        x = self.embed(tokens)
        for blk in self.blocks:
            x = blk(x)
        return x

class Decoder(nn.Module):
    def __init__(self, dim, layers, use_lora, lora_rank):
        super().__init__()
        self.blocks = nn.ModuleList([
            TransformerBlock(dim, use_lora=use_lora, lora_rank=lora_rank)
            for _ in range(layers)
        ])
        self.to_pixels = nn.Sequential(
            nn.Linear(dim, dim),
            nn.Unflatten(1, (dim, 8, 8)),
            nn.ConvTranspose2d(dim, 3, 4, 2, 1),
            nn.Sigmoid()
        )
    def forward(self, feats):
        x = feats
        for blk in self.blocks:
            x = blk(x)
        return self.to_pixels(x.mean(dim=1))

class Model(nn.Module):
    def __init__(self, vocab_size, dim, enc_layers, dec_layers, use_lora=False, lora_rank=4):
        super().__init__()
        self.enc = Encoder(vocab_size, dim, enc_layers, use_lora, lora_rank)
        self.dec = Decoder(dim, dec_layers, use_lora, lora_rank)
    def forward(self, tokens, images=None):
        feats = self.enc(tokens)
        return self.dec(feats)

def train(model, dataloader, epochs, device):
    opt = optim.AdamW(model.parameters(), lr=1e-4)
    model.to(device).train()
    for _ in range(epochs):
        for tokens, images in dataloader:
            tokens = tokens.to(device)
            images = images.to(device)
            opt.zero_grad()
            recon = model(tokens)
            loss = ((recon - images)**2).mean()
            loss.backward()
            opt.step()

def generate(model, prompt_tokens, device, steps=50):
    model.to(device).eval()
    with torch.no_grad():
        x = model.enc(prompt_tokens.to(device))
        for _ in range(steps):
            x = model.dec(x).flatten(1,2)
        return x.view(-1, 3, 64, 64)

# configurations
configs = {
    "o3": {"use_lora": True,  "lora_rank":4},
    "o4-mini": {"use_lora": True,  "lora_rank":2},
    "o4-mini-high": {"use_lora": False, "lora_rank":0}
}

# example setup
if __name__ == "__main__":
    vocab_size = 50000
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    dummy_dataset = ...  # yields (tokens, image) pairs
    loader = DataLoader(dummy_dataset, batch_size=8, shuffle=True)
    models = {}
    for name, cfg in configs.items():
        models[name] = Model(vocab_size, dim=512, enc_layers=6, dec_layers=6,
                             use_lora=cfg["use_lora"], lora_rank=cfg["lora_rank"])
        train(models[name], loader, epochs=5, device=device)
    sample_tokens = torch.randint(0, vocab_size, (1,64))
    for name, m in models.items():
        img = generate(m, sample_tokens, device)
        torch.save(img, f"{name}_generated.pt")