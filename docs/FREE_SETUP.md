# $0 Free Setup Guide for Basilisk

This guide explains how to use **Basilisk** for LLM security testing and AI red teaming completely free of charge ($0 setup) using **GitHub Models**.

GitHub Models provides free API access to AI models such as `gpt-4o-mini`, `gpt-4o`, `o3-mini`, `Phi-4`, `Llama-3.3-70B`, and more without requiring a paid subscription or credit card.

---

## Step-by-step Setup

### Step 1: Install Basilisk

Install Basilisk from PyPI:

```bash
pip install basilisk-ai
```

---

### Step 2: Get a GitHub Models Token

To use GitHub Models with Basilisk, generate a GitHub Personal Access Token with the `models:read` scope:

1. Go to GitHub's Personal Access Tokens settings:
   - **Fine-grained tokens (recommended)**: [https://github.com/settings/tokens?type=beta](https://github.com/settings/tokens?type=beta)
   - Or **Tokens (classic)**: [https://github.com/settings/tokens](https://github.com/settings/tokens)
2. Click **Generate new token**.
3. Set a descriptive name (e.g., `Basilisk Red Teaming`).
4. Under permissions / scopes, grant the **`models:read`** permission.
5. Generate the token and copy it.

---

### Step 3: Export the Environment Variable

Export the token as `GH_MODELS_TOKEN` in your terminal environment:

```bash
export GH_MODELS_TOKEN="ghp_your_token_here"
```

*(Note: Never share or commit your token to public repositories.)*

---

### Step 4: Run Basilisk with the `--free` Preset

Run a scan against your target application using the `--free` preset flag:

```bash
basilisk scan -t https://api.target.com/chat --free
```

#### What `--free` does automatically:
- Sets the provider to `github` (GitHub Models).
- Defaults the model to `gpt-4o-mini`.
- Bypasses paid API key requirements.
- Uses `GH_MODELS_TOKEN` for model inference without falling back to local providers like Ollama.

---

## Customizing Models with `--free`

While `--free` defaults to `gpt-4o-mini`, you can select any supported GitHub Models endpoint using `-m` / `--model`:

```bash
# Test using GPT-4o via GitHub Models
basilisk scan -t https://api.target.com/chat --free -m gpt-4o

# Run quick mode
basilisk scan -t https://api.target.com/chat --free --mode quick
```

---

## Troubleshooting

- **Error: `GH_MODELS_TOKEN is missing`**:
  Ensure you exported `GH_MODELS_TOKEN` in the active shell environment before running `basilisk`.
- **Permission Errors**:
  Verify your token was created with `models:read` permission.
- **Rate Limits**:
  GitHub Models applies standard free usage tiers. If rate limited, use `--mode stealth` or `--mode quick` to lower request frequency.
