# Discord APK Analysis Bot

A Discord bot designed to analyze APK files using the VirusTotal API. This bot scans and reports the security status of APK files shared in a Discord server. **Currently, the bot supports only APK files, but future updates will expand support to all file types.**

## Features

- **Automated APK analysis**: Users can upload APK files, and the bot will automatically analyze them.
- **VirusTotal API integration**: Utilizes VirusTotal to scan APKs and return detailed reports.
- **Secure and easy-to-use**: Ensures a streamlined experience within Discord.

## Getting Started

### Prerequisites

- Python 3.8 or higher
- [discord.py](https://discordpy.readthedocs.io/en/stable/) library
- A [Discord Developer Application](https://discord.com/developers/applications) with a bot token
- A valid [VirusTotal API key](https://www.virustotal.com/gui/join-us)

### Installation

1. Clone this repository:

   ```bash
   git clone https://github.com/alan7383/discord-analysis-bot.git
   cd discord-analysis-bot
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Configure your environment: Create a `.env` file in the root directory and add:

   ```env
   DISCORD_TOKEN=your-discord-bot-token
   VIRUSTOTAL_API_KEY=your-virustotal-api-key
   ```

4. Start the bot:

   ```bash
   python bot.py
   ```

## Usage
- Invite the bot to your Discord server.
- When an APK file is uploaded in the server, the bot will automatically analyze it and provide a security report from VirusTotal.

## Public Bot Invitation
If you prefer not to host the bot yourself, use the following invitation link to add the bot directly to your server (hosted by me):

**[Invite the Bot](https://discord.com/oauth2/authorize?client_id=1305980059500281856&permissions=8&integration_type=0&scope=bot)**

## Contributing
Contributions are welcome! Please submit a pull request or create an issue to discuss potential changes.

## License
This project is licensed under the MIT License.

---

Stay tuned for future updates and additional file type support!

**Upcoming Features**
- Enhanced reporting capabilities
- **Support for additional file types**
- Improved error handling and feedback

