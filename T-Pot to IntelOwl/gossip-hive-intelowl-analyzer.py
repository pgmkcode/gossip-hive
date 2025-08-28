{
  "size": 1,
  "query": {
    "match": {
      "src_ip.keyword": "<observable>"
    }
  },
  "sort": [
    {
      "@timestamp": {
        "order": "desc"
      }
    }
  ]
}

