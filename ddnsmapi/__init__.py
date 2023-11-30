#!/usr/bin/env python3
#
# DDNSM
# Copyright (C) 2023 Tomas Hlavacek (tmshlvck@gmail.com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

__version__ = '0.1.0'

from typing import Annotated,Optional,Tuple,List
from pydantic import BaseModel

from fastapi import Depends, FastAPI, Request, status, Form
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.exceptions import HTTPException,RequestValidationError
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
#from fastapi.staticfiles import StaticFiles
from passlib.context import CryptContext

import sys
import tempfile, subprocess
import logging
import zonefile_parser
import yaml
import os
import asyncio
import ipaddress
import re

def load_appconfig(config_file: str):
    with open(config_file, 'r') as fd:
        c = yaml.load(fd, Loader=yaml.SafeLoader)
    for u in c['users']:
        c['users'][u]['dyndns_rrs_authorization'] = set(c['users'][u]['dyndns_rrs_authorization'])
        c['users'][u]['domains_authorization'] = set(c['users'][u]['domains_authorization'])
    return c

config = load_appconfig(os.environ.get("DDNSM_CONFIG", '/etc/ddnsm/server.yaml'))

logcfg = {'format': '%(asctime)s %(levelname)s %(message)s'}
if config.get('debug', False):
    logcfg['level'] = logging.DEBUG
else:
    logcfg['level'] = logging.WARN

if config.get('logfile', None):
    logcfg['filename'] = config['logfile']
logging.basicConfig(**logcfg)

class Knot:
    BIN_KZONECHECK = config.get('bin_kzonecheck', '/usr/bin/kzonecheck')
    BIN_KNOTC = config.get('bin_knotc', '/usr/sbin/knotc')
    
    DEFAULT_TTL = 3600
    DEFAULT_DYN_TTL = 60

    def __init__(self, config) -> None:
        self.knot_conf_filename = config.get('knot_conf', '/etc/knot/knot-ddnsm.conf')
        self.knot_conf_mtime = 0
        self.knot_zone_dir = config.get('knot_zone_dir', '/var/lib/knot/')

        self.knot_configlock = asyncio.Lock()
        self.knot_config = None

        logging.debug(f"Knot interface initialized with conf {self.knot_conf_filename}, knotc {self.BIN_KNOTC}, kzonecheck {self.BIN_KZONECHECK}")

    async def read_config(self):
        def fixup_config():
            if not self.knot_config.get('zone',None):
                self.knot_config['zone'] = []
            if not self.knot_config.get('remote',None):
                self.knot_config['remote'] = []
            if not self.knot_config.get('acl',None):
                self.knot_config['acl'] = []

        async with self.knot_configlock:
            mtime = os.stat(self.knot_conf_filename).st_mtime
            if self.knot_conf_mtime < mtime:
                logging.debug(f"Reading knot config from file {self.knot_conf_filename}")
                self.knot_conf_mtime = mtime
                with open(self.knot_conf_filename, 'r') as fd:
                    self.knot_config = yaml.load(fd, Loader=yaml.SafeLoader)

                fixup_config()

    async def get_knot_config(self):
        await self.read_config()
        return self.knot_config
    
    async def reload_config(self):
        logging.debug("Reloading knot config")
        process = subprocess.Popen([self.BIN_KNOTC, 'reload'],
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        logging.debug(f"Knot config reload ret: {process.returncode} stdout: {stdout.decode()} stderr: {stderr.decode()}")
        if process.returncode == 0:
            return (True, f"{stdout.decode()}")
        else:
            return (False, f"{stdout.decode()} {stderr.decode()}")

    async def update_config(self):
        def fixup_output():
            kc = self.knot_config
            if kc.get('zone',None) == []:
                del kc['zone']
            if kc.get('remote',None) == []:
                del kc['remote']
            if kc.get('acl',None) == []:
                del kc['acl']

            if kc.get('server',{}).get('listen',[]):
                kc['server']['listen'] = '[' + ','.join(kc['server']['listen']) + ']'
            return kc
        
        class CustomDumper(yaml.Dumper):
            PREFERRED_KEYS = ['id','domain','target'] 
            def represent_dict_knot_order(self, data):
                result = []
                for pfk in self.PREFERRED_KEYS:
                    if data.get(pfk, None):
                        result.append((pfk, data[pfk]))
                for k, v in data.items():
                    if k in self.PREFERRED_KEYS:
                        pass
                    else:
                        result.append((k,v))
                return self.represent_dict(result)

        CustomDumper.add_representer(dict, CustomDumper.represent_dict_knot_order)

        logging.debug('Updating knot config')
        async with self.knot_configlock:
            mtime = os.stat(self.knot_conf_filename).st_mtime
            if self.knot_conf_mtime < mtime:
                raise Exception("Race condition detected: The config file has changed between last read and attempted writing.")
            with open(self.knot_conf_filename, 'r') as ifd:
                knot_conf_backup = ifd.read()

            output = yaml.dump(fixup_output(), default_style=None, default_flow_style=False, Dumper=CustomDumper)
            with open(self.knot_conf_filename, 'w') as ofd:
                ofd.write(output)

            rok, msg = await self.reload_config()
            if not rok:
                logging.error(f'Reload config failed with msg {msg}, reverting knot config')
                logging.debug(f"Failed reload with config: {output}")
                with open(self.knot_conf_filename, 'w') as ofd:
                    ofd.write(knot_conf_backup)
            else:
                logging.debug('Reload config succeeded, update finished')
            return (rok, msg)

    def is_authorized(self, user, domain):
        if user == 'root':
            return True

        if not domain:
            return False

        if config['users'].get(user,{}).get('superadmin', False) or '*' in config['users'].get(user,{}).get('domains_authorization', set()):
            return True
        elif domain in config['users'].get(user,{}).get('domains_authorization', set()):
            return True
        elif domain in config['users'].get(user,{}).get('dyndns_rrs_authorization', set()):
            return True
        else:
            return False

    async def _get_zones(self, user:str | None =None):
        kc = await self.get_knot_config()
        zones = kc.get('zone',[])
        for i,z in enumerate(zones):
            if self.is_authorized(user, z['domain']):
                yield (i,z)
            else:
                pass

    async def get_zones(self, user: str | None =None):
        return [z async for z in self._get_zones(user)]

    async def get_zone(self, zone_idx: int, user: str | None =None):
        kc = await self.get_knot_config()
        if not self.is_authorized(user, kc['zone'][zone_idx].get('domain', None)):
            logging.warning(f"User {user} not authorized to manipulate zone idx {zone_idx} ({kc['zone'][zone_idx].get('domain', '')})!")
            raise ValueError(f"User {user} not authorized to manipulate zone idx {zone_idx} ({kc['zone'][zone_idx].get('domain', '')})!")
        return kc['zone'][zone_idx]

    async def put_zone(self, zone_idx: int, config, user: str | None =None):
        kc = await self.get_knot_config()
        if not self.is_authorized(user, kc['zone'][zone_idx].get('domain', None)):
            logging.warning(f"User {user} not authorized to manipulate zone idx {zone_idx} ({kc['zone'][zone_idx].get('domain', '')})!")
            raise ValueError(f"User {user} not authorized to manipulate zone idx {zone_idx} ({kc['zone'][zone_idx].get('domain', '')})!")
        kc['zone'][zone_idx] = config

        rok, rmsg = await self.update_config()
        if not rok:
            raise RuntimeError(rmsg)

    def create_zonefile_name(self, zonename):
        return os.path.join(self.knot_zone_dir.strip(), zonename.rstrip('.').strip()+'.zone')
    
    def gen_default_rrs(self, domain):
        return [
            {'name': domain,
             'ttl': 3600,
             'rclass': 'IN',
             'rtype': 'SOA',
             'rdata': {'mname': 'this-server.'+domain, 'rname': 'root.'+domain, 'serial': 1, 'refresh': 10800, 'retry': 3600, 'expire': 604800, 'minimum': 3600},
            },
            {'name': domain,
             'ttl': 3600,
             'rclass': 'IN',
             'rtype': 'NS',
             'rdata': {'value': 'this-server.domain.tld.'},
            },
        ]

    async def create_zone(self, config, user: str | None =None):
        kc = await self.get_knot_config()
        if not self.is_authorized(user, config.get('domain', None)):
            logging.warning(f"User {user} not authorized to manupulate zone ({config.get('domain', '')})!")
            raise ValueError(f"User {user} not authorized to manupulate zone ({config.get('domain', '')})!")
        
        if not 'file' in config:
            config['file'] = self.create_zonefile_name(config['domain'])

        for z in kc['zone']:
            if z['domain'] == config['domain']:
                raise ValueError(f"Zone {config['domain']} already exists!")
            if z.get('file',None) == config['file']:
                raise ValueError(f"Zone file {config['file']} is already used by another zone!")

        kc['zone'].append(config)
        zone_idx = len(kc['zone'])-1

        rok, rmsg = await self.update_config()
        if not rok:
            raise RuntimeError(rmsg)
        
        await self.put_rrs(zone_idx, self.gen_default_rrs(config['domain']), user)

    async def delete_zone(self, zone_idx: int, user: str | None =None):
        ztd = await self.get_zone(zone_idx, user)
        if ztd.get('file', None) and os.path.exists(ztd['file']):
            os.unlink(ztd['file'])
        #else:
        #    raise ValueError(f'Zone file does not exist for zone_idx {zone_idx}.')

        del self.knot_config['zone'][zone_idx]
        rok, rmsg = await self.update_config()
        if not rok:
            raise RuntimeError(rmsg)

        return ztd
    
    async def get_remotes(self):
        kc = await self.get_knot_config()
        return list(enumerate(kc['remote']))

    async def get_rrs(self, zone_idx: int, user: str | None =None):
        z = await self.get_zone(zone_idx, user)
        if not z.get('file', None):
            logging.warning(f'Zone file is not set for zone_idx {zone_idx}.')
            raise ValueError(f'Zone file is not set for zone_idx {zone_idx}.')

        try:
            with open(z['file'], 'r') as fd:
                return [r.__repr__() for r in zonefile_parser.parse(fd.read())]
        except FileNotFoundError as e:
            logging.debug(f"Reading zone file {z['file']} failed: {str(e)}. Returning empty list.")
            return []

    async def zonecheck(self, zone, zonelines):
        logging.debug(f"Running zonecheck for {zone['domain']}")
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as fp:
            for l in zonelines:
                print(l, file=fp)
            fp.close()

            logging.debug(f"Running zonecheck on file {fp.name}")

            try:
                process = subprocess.Popen([self.BIN_KZONECHECK, '-v', '-o', zone['domain'], fp.name],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
            finally:
                if os.path.exists(fp.name):
                    os.unlink(fp.name)

            if process.returncode == 0:
                logging.debug(f"Zonecheck succeeded on file {fp.name}")
                return (True, f"{stdout.decode()}")
            else:
                logging.warning(f"Zonecheck failed on file {fp.name}: {stdout.decode()} {stderr.decode()}")
                logging.debug(f"Zonecheck failed on content {str(zonelines)}")
                return (False, f"{stdout.decode()} {stderr.decode()}")
    
    async def reload_zone(self, zone):
        logging.debug(f"Running zone reload for {zone['domain']}")
        
        process = subprocess.Popen([self.BIN_KNOTC, 'zone-reload', zone['domain']],
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode == 0:
            logging.debug(f"Zone reload succeeded for {zone['domain']}")
            return (True, f"{stdout.decode()}")
        else:
            logging.error(f"Zone reload failed for {zone['domain']}: {stdout.decode()} {stderr.decode()}")
            return (False, f"{stdout.decode()} {stderr.decode()}")
    
    def _gen_zone_lines(self, zone, records):
        yield f"$ORIGIN {zone['domain']};"
        yield f"$TTL {self.DEFAULT_TTL};"
        for rr in records:
            if rr['rtype'] == 'SOA':
                yield f"{rr['name']}	{rr['ttl']}	{rr['rclass']}	SOA	{rr['rdata']['mname']} {rr['rdata']['rname']} {rr['rdata']['serial']} {rr['rdata']['refresh']} {rr['rdata']['retry']} {rr['rdata']['expire']} {rr['rdata']['minimum']}"
            elif rr['rtype'] == 'MX':
                yield f"{rr['name']}	{rr['ttl']}	{rr['rclass']}	MX	{rr['rdata']['priority']} {rr['rdata']['host']}"
            elif rr['rtype'] == 'CAA':
                 yield f"{rr['name']}	{rr['ttl']}	{rr['rclass']}	MX	{rr['rdata']['flag']} {rr['rdata']['tag']} {rr['rdata']['value']}"
            elif rr['rtype'] == 'SRV':
                 yield f"{rr['name']}	{rr['ttl']}	{rr['rclass']}	MX	{rr['rdata']['priority']} {rr['rdata']['weight']} {rr['rdata']['port']} {rr['rdata']['host']}"
            else:
                rdstr = ' '.join([rr['rdata'][rdk] for rdk in rr['rdata']])
                yield f"{rr['name']}	{rr['ttl']}	{rr['rclass']}	{rr['rtype']}	{rdstr}"

    @staticmethod
    def update_soa_serial(oldrrs, newrrs):
        oldserial = 1
        try:
            for orr in oldrrs:
                if orr['rtype'] == 'SOA':
                    oldserial = int(orr['rdata']['serial'])
        except:
            pass
        for nrr in newrrs:
            if nrr['rtype'] == 'SOA':
                if int(nrr['rdata']['serial']) == oldserial:
                    nrr['rdata']['serial'] = int(nrr['rdata']['serial'])+1


    async def put_rrs(self, zone_idx: int, records, user: str | None =None, update_serial: bool =True):
        z = await self.get_zone(zone_idx, user)
        if not z['file']:
            logging.warning(f'Zone file is not set for zone_idx {zone_idx}.')
            raise ValueError(f'Zone file is not set for zone_idx {zone_idx}.')
        
        oldrrs = await self.get_rrs(zone_idx, user)
        self.update_soa_serial(oldrrs, records)
        
        zstr = list(self._gen_zone_lines(z, records))
        
        zok, zckmsg = await self.zonecheck(z, zstr)
        if not zok:
            raise Exception("Zone chack failed: "+zckmsg)

        with open(z['file'], 'w') as ofd:
            for zl in zstr:
                print(zl, file=ofd)
        logging.debug(f"Zone {z['domain']} written to file {z['file']}")

        return await self.reload_zone(z)

    async def put_rr(self, zone_idx: int, rr_idx: int, rr, user: str | None =None):
        logging.debug(f'Udating RR in zone {zone_idx} rridx {rr_idx} rr {str(rr)} by user {user}')
        rrs = await self.get_rrs(zone_idx, user)
        rrs[rr_idx] = rr
        await self.put_rrs(zone_idx, rrs, user)

    async def create_rr(self, zone_idx: int, rr, user: str | None =None):
        logging.debug(f'Create RR in zone {zone_idx} rr {str(rr)} by user {user}')
        rrs = await self.get_rrs(zone_idx, user)
        rrs.append(rr)
        await self.put_rrs(zone_idx, rrs, user)

    async def delete_rr(self, zone_idx: int, rr_idx: int, user: str | None =None):
        logging.debug(f'Deleting RR in zone {zone_idx} rridx {rr_idx} by user {user}')
        rrs = await self.get_rrs(zone_idx, user)
        del rrs[rr_idx]
        await self.put_rrs(zone_idx, rrs, user)

    @staticmethod
    def fqdn(rr_name: str, zone_name: str | None =None):
        res = rr_name.lower().rstrip('.').strip()
        res += '.'
        if zone_name:
            zone_name = zone_name.lower().lstrip('.').rstrip('.').strip() + '.'
            if rr_name.strip().endswith('.'):
                if not res.endswith('.'+zone_name):
                    raise ValueError(f'RR {rr_name} is FQDN but it is not a part of zone {zone_name}')
            else:
                res += zone_name
        return res

    async def find_zone_for_domain(self, domain: str, user: str | None =None):
        match_len = -1
        match_idx = None
        match_z = None
        norm_domain = self.fqdn(domain)
        for zidx, z in await self.get_zones(user):
            zfqdn = self.fqdn(z['domain'])
            if norm_domain.endswith('.'+zfqdn) and len(zfqdn) > match_len:
                match_len = len(zfqdn)
                match_idx = zidx
                match_z = z
        if match_z:
            return (match_idx, match_z)
        else:
            logging.error(f"No zone found for domain {domain}!")
            raise RuntimeError(f"No zone found for domain {domain}!")

    async def dyndns_update_rr(self, domain: str, ip: str, user: str | None =None):
        if not self.is_authorized(user, domain):
            logging.warning(f"User {user} not authorized to manipulate domain ({domain})!")
            raise ValueError(f"User {user} not authorized to manipulate domain ({domain})!")

        ipa = ipaddress.ip_address(ip)
        if ipa.version == 6:
            rtype = 'AAAA'
        elif ipa.version == 4:
            rtype = 'A'
        else:
            logging.error(f"Unknown IP AFI: {ipa.version}")
            raise ValueError(f"Unknown IP AFI: {ipa.version}")
        
        zidx, z = await self.find_zone_for_domain(domain, 'root')
        rrs = await self.get_rrs(zidx, 'root')
        
        fqdn_domain = self.fqdn(domain)

        update_rridx = None
        for rridx, rr in enumerate(rrs):
            if rr['rtype'] == rtype and self.fqdn(rr['name'], z['domain']) == fqdn_domain:
                update_rridx = rridx
                break
        if update_rridx:
            if rrs[update_rridx]['rdata']['value'] != ip:
                rrs[update_rridx]['rdata']['value'] = ip
                await self.put_rrs(zidx, rrs, 'root')
                return "updated"
            else:
                return "noop"
        else:
            new_rr = {'name': fqdn_domain, 'ttl': str(self.DEFAULT_DYN_TTL), 'rclass': 'IN', 'rtype': rtype, 'rdata': {'value': ip }}
            await self.create_rr(zidx, new_rr, 'root')
            return "created"

RE_ALLOWED_DNS_NAME_CHARS = re.compile(r'[A-Za-z0-9\.-]')

class Zone(BaseModel):
    domain: str
    file: Optional[str] =None
    acl: Optional[str] =None
    notify: Optional[str] =None
    master: Optional[str] =None
    storage: Optional[str] =None

    def gen_zonedict(self):
        d = dict(self)
        fd = {k:d[k] for k in d if d[k] != None}
        fd['domain'] = Knot.fqdn(fd['domain'])

        return fd

class RdataSOA(BaseModel):
    mname: str
    rname: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int

    def validate(self):
        return True

class RdataMX(BaseModel):
    priority: int
    host: str

    def validate(self):
        return True

class RdataCAA(BaseModel):
    flag: int
    tag: str
    value: str

    def validate(self):
        return True

class RdataSRV(BaseModel):
    priority: int
    weight: int
    port: int
    host: str

    def validate(self):
        return True

class Rdata(BaseModel):
    value: str

    def validate(self):
        return True

class RR(BaseModel):
    name: str
    rclass: str
    rtype: str
    ttl: int
    rdata: Rdata | RdataMX | RdataSOA | RdataCAA | RdataSRV

    def validate(self):
        self.name = self.name.strip().lower()
        if not RE_ALLOWED_DNS_NAME_CHARS.match(self.name):
            raise ValueError(f"Domain name {self.name} contains unexpected characters. See ")
        if len(self.name) < 2:
            raise ValueError(f"Domain name {self.name} is too short. Minimum 2 characters.")
        
        return self.rdata.validate()

class Status(BaseModel):
    success: bool
    message: str | None
    errors: List[str]

class LogData(BaseModel):
    entries: int
    data: List[str]

class Remote(BaseModel):
    id: str
    address: str


def create_app(config):
    knot = Knot(config)
    app = FastAPI(root_path=config.get('root_path','/'))
    security = HTTPBasic()
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

## DEBUGGING FACILITY - remove from production code
#    @app.exception_handler(RequestValidationError)
#    async def validation_exception_handler(request: Request, exc: RequestValidationError):
#        exc_str = f'{exc}'.replace('\n', ' ').replace('   ', ' ')
#        # or logger.error(f'{exc}')
#        print(request, exc_str)
#        content = {'status_code': 10422, 'message': exc_str, 'data': None}
#        return JSONResponse(content=content, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)

    async def check_creds(creds):
        if not config.get('authentication'):
            return None
        if creds.username in config['users'] and \
            pwd_context.verify(creds.password, config['users'][creds.username].get('hashed_password', '')):
            return creds.username
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Basic"})

    @app.get(config.get('prefix','')+"/zones")
    async def get_zones(creds: Annotated[HTTPBasicCredentials, Depends(security)]) -> List[Tuple[int,Zone]]:
        user = await check_creds(creds)
        return await knot.get_zones(user)
    
    @app.get(config.get('prefix','')+"/remotes")
    async def get_remotes(creds: Annotated[HTTPBasicCredentials, Depends(security)]) -> List[Tuple[int,Remote]]:
        user = await check_creds(creds)
        return await knot.get_remotes()
        
    @app.post(config.get('prefix','')+"/zone")
    async def post_zone(creds: Annotated[HTTPBasicCredentials, Depends(security)], zone: Zone) -> Status:
        user = await check_creds(creds)
    
        try:
            z = zone.gen_zonedict()
            await knot.create_zone(z, user)
        except Exception as e:
            logging.exception("Exception in post_zone:")
            return Status(success=False, message=None, errors=[f"Failed to create zone {zone.domain}:", str(e)])
        else:
            logging.debug(f"Zone {zone.domain} created!")
            return Status(success=True, message=f"Zone {zone.domain} created!", errors=[])
    
    @app.delete(config.get('prefix','')+"/zone/{zone_id}")
    async def del_zone(creds: Annotated[HTTPBasicCredentials, Depends(security)], zone_id: int) -> Status:
        user = await check_creds(creds)

        try:
            await knot.delete_zone(zone_id, user)
        except Exception as e:
            logging.exception("Exception in del_zone:")
            return Status(success=False, message=None, errors=[f"Failed to delete zone {zone_id}:", str(e)])
        else:
            logging.debug(f"Zone {zone_id} deleted!")
            return Status(success=True, message=f"Zone {zone_id} deleted!", errors=[])

    @app.get(config.get('prefix','')+"/zone/{zone_id}/rrs")
    async def get_rrs(creds: Annotated[HTTPBasicCredentials, Depends(security)], zone_id: int) -> List[Tuple[int,RR]]:
        user = await check_creds(creds)
        return [(i,RR.model_validate(rr)) for i,rr in enumerate(await knot.get_rrs(zone_id, user))]

    @app.post(config.get('prefix','')+"/zone/{zone_id}/rr")
    async def post_rr(creds: Annotated[HTTPBasicCredentials, Depends(security)], zone_id: int, rr: RR) -> Status:
        print(str(rr))
        user = await check_creds(creds)
        try:
            rr.validate()
            await knot.create_rr(zone_id, rr.model_dump(), user)
        except Exception as e:
            logging.exception("Exception in post_rr:")
            return Status(success=False, message=None, errors=[f"Failed to create new RR in zone {zone_id}:", str(e)])
        else:
            logging.debug(f"RR in zone {zone_id} created!")
            return Status(success=True, message=f"RR in zone {zone_id} created!", errors=[])

    @app.put(config.get('prefix','')+"/zone/{zone_id}/rr/{rr_id}")
    async def put_rr(creds: Annotated[HTTPBasicCredentials, Depends(security)], zone_id: int, rr_id: int, rr: RR) -> Status:
        user = await check_creds(creds)
        try:
            rr.validate()
            await knot.put_rr(zone_id, rr_id, rr.model_dump(), user)
        except Exception as e:
            logging.exception("Exception in put_rr:")
            return Status(success=False, message=None, errors=[f"Failed to update RR {rr_id} in zone {zone_id}:", str(e)])
        else:
            logging.debug(f"RR {rr_id} in zone {zone_id} updated!")
            return Status(success=True, message=f"RR {rr_id} in zone {zone_id} updated!", errors=[])
    
    @app.delete(config.get('prefix','')+"/zone/{zone_id}/rr/{rr_id}")
    async def delete_rr(creds: Annotated[HTTPBasicCredentials, Depends(security)], zone_id: int, rr_id: int) -> Status:
        user = await check_creds(creds)
        try:
            await knot.delete_rr(zone_id, rr_id, user)
        except Exception as e:
            logging.exception("Exception in delete_rr:")
            return Status(success=False, message=None, errors=[f"Failed to delete RR {rr_id} in zone {zone_id}:", str(e)])
        else:
            logging.debug(f"RR {rr_id} in zone {zone_id} deleted!")
            return Status(success=True, message=f"RR {rr_id} in zone {zone_id} deleted!", errors=[])

    @app.get(config.get('prefix','')+"/logs")
    async def get_logs(creds: Annotated[HTTPBasicCredentials, Depends(security)], page: Optional[int] =0, pageEntries: Optional[int] =100) -> LogData:
        user = await check_creds(creds)
        entries = 0
        data = []
        if config.get('logfile', None):
            with open(config['logfile'], 'r') as fd:
                for i,l in enumerate(fd.readlines()):
                    entries = i
                    if i >= page*pageEntries and i < (page+1)*pageEntries:
                        data.append(l)
        return LogData(entries=entries, data=data)

# DynDNS Example HTTP query:
# POST /nic/update?hostname=subdomain.yourdomain.com&myip=1.2.3.4 HTTP/1.1
# Host: domains.google.com
# Authorization: Basic base64-encoded-auth-string

    @app.get(config.get('prefix','')+"/ddns/update")
    @app.get(config.get('prefix','')+"/update")
    async def get_ddns_update(creds: Annotated[HTTPBasicCredentials, Depends(security)], hostname: str, myip: str):
        user = await check_creds(creds)
        logging.info(f"DYNDNS GET update: user {user} hostname {hostname} myip: {myip}")
        try:
            status = await knot.dyndns_update_rr(knot.fqdn(hostname), myip.lower().strip(), user)
        except Exception as e:
            logging.exception("DYNDNS GET update failed:")
            return {'success': False, 'message': 'failed'}

        logging.info(f"DYNDNS GET update succeeded, message: {status}")
        return {'success': True, 'message': status}

##    Removed as redundant and unneeded
#    @app.post("/ddns/update")
#    async def post_ddns_update(creds: Annotated[HTTPBasicCredentials, Depends(security)], hostname: Annotated[str, Form()], myip: Annotated[str, Form()]):
#        user = await check_creds(creds)
#        logging.info(f"DYNDNS POST update: user {user} hostname {hostname} myip: {myip}")
#        try:
#            status = await knot.dyndns_update_rr(knot.fqdn(hostname), myip.lower().strip(), user)
#        except:
#            logging.warning(f"DYNDNS POST update failed!")
#            return {'success': False, 'message': 'failed'}
#
#        logging.info(f"DYNDNS POST update succeeded, message: {status}")
#        return {'success': True, 'message': status}
#    

    # Web app section
    #@app.get(config.get('prefix','')+"/", response_class=HTMLResponse)
    #async def get_root(creds: Annotated[HTTPBasicCredentials, Depends(security)]):
    #    await check_creds(creds)
    #    return RedirectResponse(url=config.get('prefix','')+"/static/index.html", status_code=status.HTTP_302_FOUND)
    #
    #app.mount(config.get('prefix','')+"/static", StaticFiles(directory="static"), name="static")

    templates = Jinja2Templates(directory="static")
    
    @app.get(config.get('prefix','')+"/", response_class=HTMLResponse)
    async def get_root(request: Request, creds: Annotated[HTTPBasicCredentials, Depends(security)]):
        await check_creds(creds)
        return templates.TemplateResponse("index.html", {"request": request, "prefix": config.get('prefix', '')})

    return app

app = create_app(config)

def main():
    import uvicorn
    uvicorn.run(app, host=config.get("listen_address", "127.0.0.1"), port=config.get("listen_port", 8000), proxy_headers=True)
    return 0

if __name__ == '__main__':
    sys.exit(main())