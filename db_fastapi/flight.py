from serpapi import GoogleSearch
import json

params = {
  "engine": "google_flights",
  "hl": "en",
  "gl": "us",
  "departure_id": "CDG",
  "arrival_id": "AUS",
  "outbound_date": "2024-10-31",
  "currency": "USD",
  "type": "2",
  "api_key": "1cd54f6f71501abf5660b223bf5dbf70b3e3ffa86e5b07bd2ae994a3e1e76f96"
}

search = GoogleSearch(params)
results = search.get_dict()

with open("flight.json",'w') as f:
    json.dump(results, f)