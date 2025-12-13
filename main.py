import argparse
import asyncio
import dateutil
from google.cloud import storage
import itertools
import json
import os
import sys
from telegram import constants, Bot
import time
import yaml


def _fetch_osv_updated_list(config_osv: dict) -> list:	
	client = storage.Client.create_anonymous_client()
	
	bucket = client.bucket(config_osv["bucket"])
	print("bucket.exists", bucket.exists())
	if bucket.exists() is False:
		exit(-1)
	
	blob = bucket.get_blob(config_osv["blob"])
	print("blob.exists", blob.exists())
	if blob.exists() is False:
		exit(-1)
	
	text = blob.download_as_text()
	lines = text.split("\n")
	return lines

def _fetch_mal_ids(config: dict, osv_updated_list: list) -> list:
	cves = []
	for line in osv_updated_list:
		if "MAL-" not in line:
			continue
	
		timestamp, mal_package_cve = line.split(",")
		timestamp = dateutil.parser.parse(timestamp)
		if config["last_timestamp"] > timestamp:
			break
	
		cves.append(mal_package_cve)
	config["last_timestamp"] = dateutil.parser.parse(osv_updated_list[0].split(",")[0])
	return cves

def main() -> int:
	parser = argparse.ArgumentParser(prog="Malicious package monitor")
	parser.add_argument('config', help='Config file in yaml format')
	args = parser.parse_args()

	with open(args.config, "r") as file:
		config = yaml.safe_load(file)

	osv_updated_list = _fetch_osv_updated_list(config["osv"])
	cves = _fetch_mal_ids(config, osv_updated_list)

	print("len(cves)", len(cves))
	if cves == []:
		return 0

	for cves_batched in itertools.batched(cves, config["telegram"]["cves_batch_size"]):
		msg = f"Updated malicious package entries:\n\n```json\n{json.dumps(cves_batched, indent=4)}\n```"
		bot = Bot(os.environ["BOT_TOKEN"])
		asyncio.run(bot.send_message(config["telegram"]["channel_id"], msg, parse_mode=constants.ParseMode.MARKDOWN_V2))
		time.sleep(1)

	with open(args.config, 'w') as outfile:
		yaml.dump(config, outfile)

	return 0

if __name__ == '__main__':
    sys.exit(main())
