import discord
import requests
import os
import time
import asyncio
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

# Obtenir le token et la clé API depuis les variables d'environnement
TOKEN = os.getenv('DISCORD_TOKEN')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

headers = {
    'x-apikey': VIRUSTOTAL_API_KEY
}

intents = discord.Intents.default()
intents.messages = True
intents.message_content = True
client = discord.Client(intents=intents)

@client.event
async def on_ready():
    print(f'Bot connecté en tant que {client.user}')

@client.event
async def on_message(message):
    if message.attachments:
        for attachment in message.attachments:
            if attachment.filename.endswith('.apk'):
                await message.channel.send(f'Analyse du fichier {attachment.filename} en cours...')
                
                # Télécharge le fichier APK
                file_path = f'./{attachment.filename}'
                await attachment.save(file_path)

                # Envoie le fichier à VirusTotal
                with open(file_path, 'rb') as file_data:
                    files = {'file': (attachment.filename, file_data)}
                    response = requests.post('https://www.virustotal.com/api/v3/files', headers=headers, files=files)

                # Vérifie la réponse
                if response.status_code == 200:
                    file_id = response.json().get('data', {}).get('id')
                    analysis_complete = False
                    attempts = 0  # Compteur pour limiter le nombre de tentatives

                    # Limite à 12 vérifications (environ 2 minutes)
                    while not analysis_complete and attempts < 12:
                        report_response = requests.get(f'https://www.virustotal.com/api/v3/analyses/{file_id}', headers=headers)
                        if report_response.status_code == 200:
                            analysis_result = report_response.json()
                            status = analysis_result['data']['attributes']['status']
                            
                            if status == 'completed':
                                analysis_complete = True
                                stats = analysis_result['data']['attributes']['stats']
                                positives = stats['malicious']
                                total = sum(stats.values())
                                
                                await message.channel.send(f'Analyse terminée : {positives}/{total} moteurs ont détecté le fichier comme dangereux.')
                            else:
                                await asyncio.sleep(5)  # Attente de 10 secondes avant de vérifier à nouveau
                                attempts += 1
                        else:
                            await message.channel.send('Erreur lors de la récupération du rapport.')
                            break

                    if not analysis_complete:
                        await message.channel.send('L\'analyse a pris trop de temps. Veuillez réessayer plus tard.')

                else:
                    await message.channel.send('Erreur lors de l\'envoi du fichier à VirusTotal.')

                # Supprime le fichier temporaire
                os.remove(file_path)

client.run(TOKEN)
