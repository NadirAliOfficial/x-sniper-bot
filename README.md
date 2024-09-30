# X Sniper Bot

A Telegram-based crypto sniper bot that monitors X (Twitter) posts in real time, extracts contract addresses or wallet addresses, and automatically executes buy or transfer transactions on supported chains.

![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=flat&logo=python&logoColor=white)
![Telegram](https://img.shields.io/badge/Telegram-Bot-26A5E4?style=flat&logo=telegram&logoColor=white)

## Features

- Monitors configured X accounts or keywords via Telegram feed
- Regex-based contract address detection (EVM, Solana)
- Auto-executes buy transactions with configurable amount
- Chain-agnostic: configure for ETH, BSC, Solana, or others
- Address deduplication — won't buy the same contract twice per session
- Logs all detected addresses and transaction results

## Setup

1. Clone the repo and install dependencies:

```bash
pip install telethon python-dotenv
```

2. Copy `.env.example` to `.env` and fill in:

```env
TELEGRAM_API_ID=your_api_id
TELEGRAM_API_HASH=your_api_hash
WALLET_PRIVATE_KEY=your_private_key
BUY_AMOUNT_ETH=0.01
TARGET_CHANNELS=channel1,channel2
```

3. Run:

```bash
python bot.py
```

## Files

| File             | Purpose                                      |
|------------------|----------------------------------------------|
| `bot.py`         | Main bot — monitors Telegram, triggers buys  |
| `addresses.py`   | Address extraction and chain detection logic |
| `test_detect.py` | Unit tests for address pattern matching      |

## Security

Never commit your `.env` file or private keys. Use a dedicated hot wallet with limited funds.

## License

MIT


