# DDNSM-Server / DDNSMAPI

Knot-based DDNS server with API and WebApp for zone and RR management.

Originally this serever has been built for [DDNSM client](https://github.com/tmshlvck/ddnsm). However the
server implements generic semi-standard DDNS update API via HTTP(S) GET (`/ddns/update`) with URL-encoded
`hostname` and `myip` parameters and therefore it can be potentially used with many other clients.

## Server installation (Git)

### Requirements / prerequisities

* Modern Ubuntu (22.04 or newer) or Debian (bookworm or later).
* Knot 3.0+
* kzonecheck (usually in package knot-dnsutils)
* Python 3.9+
* systemd
* pip
* poetry

### Installation of packages

Install packages:
```
sudo apt-get install knot knot-dnsutils python3-pip python3-poetry git
```

### Installation from Git

Create server directory and clone this repo:
```
sudo mkdir -p /var/lib/ddnsm
cd /var/lib/ddnsm
sudo git clone https://github.com/tmshlvck/ddnsmapi.git
chown -R knot:knot /var/lib/ddnsm
sudo -u knot poetry build
sudo pip install dist/ddnsmapi-*-py3-none-any.whl
sudo mkdir /etc/ddnsm/
```

### Configuration
Configure knot:
```
sudo touch /etc/knot/knot-ddnsm.conf
sudo bash -c 'echo "include: knot-ddnsm.conf" >> /etc/knot/knot.conf'
sudo chown knot:knot /etc/knot/knot-ddnsm.conf
```

Copy and modify DDNSMAPI config file `cp tests/server-ubuntu.yaml /etc/ddnsm/server.yaml`.
To create the users you need to create bcrypt hashes. Either use Python REPL to call bcrypt:

```
from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
pwd_context.hash("PASSWORD-TO-HASH")
```

or use [ddnsm](https://github.com/tmshlvck/ddnsm) :
```
[th@hroch ddnsmapi]$ ddnsm --hash SECRET-PASSWORD
$2b$12$D/VzGP4lcUyRX4CzJ0a0.OFBjLltBBODt9LqQ5Nu8l/quM9stcbmi
```

Deploy, enable and start systemd unit:
```
sudo cp ddnsmapi.service /etc/systemd/system/ddnsmapi.service
sudo systemctl daemon-reload
sudo systemctl enable ddnsmapi
sudo systemctl start ddnsmapi
```

Create NGINX proxy and use Certbot to create SSL certificate for the domain. The DDNS update protocol uses
Basic Authentication that transmits passwords as plain-text and therefore it would be absolutely insecure
and prone to all kinds of MITM attacks without HTTPS.

Add proxy section to your NGINX site (i.e. `/etc/nginx/sites-enabled/default`): 

```
server {
...
  location /ddns/ {
    proxy_pass http://localhost:8000/ddns/;
    proxy_http_version 1.1;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Upgrade $http_upgrade;
    proxy_redirect off;
    proxy_buffering off;
  }
...
}
```

And do not forget to use Certbot to generate the certificates and modify the config to redirect HTTP
(insecure) connections to HTTPS:
```
certbot --nginx -d server.domain.tld
```

And add logrotate prescription for the `/var/lib/knot/ddnsm-server.log` file (modify the path
according to your `server.yaml` config):

```
sudo bash -c `cat <<EOF >/etc/logrotate.d/ddnsmapi
/var/lib/knot/ddnsm-server.log {
	weekly
	missingok
	rotate 52
	compress
	delaycompress
	notifempty
	create 0664 knot knot
}
EOF
'
```


## Alternative deployment: Docker/Podman
TBD

There is a Dockerfile that runs the API + WebApp server, but no knot server so far.
Therefore it is usable for testing only now.