# check_ip

This is a simple python script that checks IPinfo and spur.us for information about an IP address.
It helps to identify the location of the IP address, the organization that owns the IP address, the IP address's ASN and if it is associated with a known threat or commercial VPN.

# Getting Started

* To get started, clone the repository and install the requirements.

You might want to create a [`venv`](https://docs.python.org/3/library/venv.html) before installing the dependencies.

```bash
pip install -r requirements.txt
```

## Edit the config file
```
cp secrets-sample.json secrets.json
```

* Fill the optionnal values (including proxy if needed) in the `secrets.json` file. This values will be useful for `spur_us_api.py` script. It is optional to fill the `ipinfo_token` value, but it is recommended to fill it to avoid rate limit.

```json
{
    "spur_email": "youruser@example.com",
    "spur_password": "yourpassword",
    "ipinfo_token": "token",
    "proxy_url": ""
}
```

**Note:** if you don't have any account or token to use, try out the `check_ip_free.py` script, that doesn't require any token or account, only proxy if needed. It may have a lot of limitations in terms of requests and information (e.g. IP blocked or rate limit).

## Usage

```bash
python3 check_ip.py -h
usage: check_ip.py [-h] [-a IP] [-i INPUT_FILE]

Get IP information

options:
  -h, --help            show this help message and exit
  -a IP, --ip-address IP
                        IP address to check
  -i INPUT_FILE, --input-file INPUT_FILE
                        File containing IP addresses to check
```

## Tests

```bash
python3 check_ip.py -i tests/tests.txt
```

* Output

```
+-------------------+--------------------------+
|        Key        |          Value           |
+-------------------+--------------------------+
|         IP        |         1.1.1.1          |
|        City       |        The Rocks         |
|       Region      |     New South Wales      |
|      Country      |            AU            |
|      Location     |    -33.8592,151.2081     |
|        ISP        | AS13335 Cloudflare, Inc. |
|       Postal      |           2000           |
|      Timezone     |     Australia/Sydney     |
| VPN Vendor (Spur) |      Not Anonymous       |
+-------------------+--------------------------+

+-------------------+----------------------------+
|        Key        |           Value            |
+-------------------+----------------------------+
|         IP        |       45.154.138.91        |
|        City       |         Marseille          |
|       Region      | Provence-Alpes-Côte d'Azur |
|      Country      |             FR             |
|      Location     |       43.2970,5.3811       |
|        ISP        |   AS206092 IPXO LIMITED    |
|       Postal      |           13000            |
|      Timezone     |        Europe/Paris        |
| VPN Vendor (Spur) |        Express VPN         |
+-------------------+----------------------------+
```
