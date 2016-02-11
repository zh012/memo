import os
import json
from itertools import chain
from fabric import colors
from fabric.api import env, task, sudo, local, run, abort, cd, puts, fastprint, roles, parallel, put, get, settings, execute
from fabric.contrib.files import sed, exists
import boto.ec2
import pandas as pd
import re


def bgsudo(cmd, **kwargs):
    return sudo('nohup {} & sleep 5; exit 0'.format(cmd), **kwargs)


here = os.path.dirname(__file__)
default_config_file = os.path.join(here, 'localdata/settings.json')

env.files_dir = os.path.join(here, 'files')

env.roledefs = {
    'worker': []
}


try:
    env.update(json.loads(open(default_config_file, 'r').read()))
except:
    pass


def _get_connection(config):
    return boto.ec2.connect_to_region(
        config.region,
        aws_access_key_id=config.aws_access_key_id,
        aws_secret_access_key=config.aws_secret_access_key)


def _encode_nodename(tag, index):
    return '{}_{:03}'.format(tag, index)


def _decode_nodename(name):
    try:
        tag, index = name.split('_')
        return tag, int(index)
    except:
        return name, -1


def _is_node(instance, tag):
    name = instance.tags.get('Name', '')
    return _decode_nodename(name)[0] == tag


def _get_instances(conn, tag=None, names=None, instance_ids=None, include_terminated=False):
    instances = list(chain(*[r.instances for r in conn.get_all_instances(instance_ids=instance_ids)]))
    if tag:
        instances = filter(lambda i: _is_node(i, tag), instances)
    if names is not None:
        instances = filter(lambda i: i.tags.get('Name', '') in names, instances)
    if not include_terminated:
        instances = filter(lambda i: i.state != 'terminated', instances)
    return instances


def _get_spot_instance_ids(conn):
    requests = conn.get_all_spot_instance_requests()
    return filter(None, [r.instance_id for r in requests])


def _get_max_index(conn, typ):
    existing_instances = _get_instances(conn, typ)
    if existing_instances:
        max_ind = max([_decode_nodename(i.tags.get('Name', ''))[1] for i in existing_instances])
    else:
        max_ind = -1
    return max_ind


def _cls():
    fastprint('\x1b[2J\x1b[H')


def _print_instances(instances):
    from prettytable import PrettyTable
    INSTANCE_STATE_FNS = {
        'running': colors.green,
        'terminated': lambda s: colors.red(s, bold=True),
        'stopped': lambda s: colors.red(s, bold=True),
        'stopping': colors.yellow,
        'pending': colors.blue,
        'shutting-down': colors.yellow,
    }

    colorize = lambda state: INSTANCE_STATE_FNS.get(state, lambda s: s)
    table = PrettyTable(map(lambda s: colors.cyan(s, bold=True), ['name', 'id', 'ip address', 'zone', 'type', 'state']))
    rows = [
        [i.tags.get('Name', ''), i.id, i.ip_address, i.placement, i.instance_type, i.state]
        for i in instances
    ]
    for r in rows:
        table.add_row(map(colorize(r[-1]), r))
    puts(table)


def _print_bid_requests(requests):
    from prettytable import PrettyTable
    table = PrettyTable(map(lambda s: colors.cyan(s, bold=True), ['name', 'id', 'instance', 'state', 'status', 'max price', 'type', 'zone']))
    rows = [
        [i.tags.get('Name', ''), i.id or '', i.instance_id or '', i.state, i.status.code, i.price, i.launch_specification.instance_type, i.launched_availability_zone or i.launch_specification.placement or '']
        for i in requests
    ]
    for r in rows:
        table.add_row(r)
    puts(table)


def _put_file(filename, use_sudo=True):
    remote_file = filename.replace('_', '/')
    if not remote_file.startswith('/'):
        remote_file = '~/' + remote_file
    folder, name = os.path.split(remote_file)
    (use_sudo and sudo or run)('mkdir -p ' + folder)
    put(os.path.join(env.files_dir, filename), remote_file, use_sudo=True)
    if use_sudo:
        sudo('chown root:root ' + remote_file)


def _to_bool(val):
    if val is not None:
        val = val.lower()
        if val in ['y', 't', 'yes', 'true', 'n', 'f', 'no', 'false']:
            return val[0] in 'yt'


def _node_name():
    node_name = env.host_string
    for i in env.instances:
        if i.ip_address == node_name:
            node_name = i.tags.get('Name', '') or node_name
    return node_name


@task
def config(config_file=None, **kwargs):
    if config_file:
        env.update(json.loads(open(config_file, 'r').read()))
    env.update(kwargs)


@task
def nodes(typ=None, names=None, spot=None, export=False, running=None, lead=None):
    if names:
        names = filter(None, names.split(';'))
    conn = _get_connection(env)
    instances = _get_instances(conn, typ, names)

    spot = _to_bool(spot)
    if spot is not None:
        spot_instance_ids = _get_spot_instance_ids(conn)
        if spot:
            instances = filter(lambda i: i.id in spot_instance_ids, instances)
        else:
            instances = filter(lambda i: i.id not in spot_instance_ids, instances)

    running = _to_bool(running)
    if running is not None:
        instances = filter(lambda i: not ((i.state == 'running') ^ running), instances)

    instances = sorted(instances, key=lambda i: i.tags.get('Name', ''))

    lead = _to_bool(lead)
    if lead is not None:
        if lead:
            instances = instances[:1]
        else:
            instances = instances[1:]

    _print_instances(instances)
    env.roledefs['worker'] = filter(None, [i.ip_address for i in instances])
    if export:
        env.hosts = env.roledefs['worker']
    env.instances = instances


@task
def tag(typ=None, mode='u'):
    conn = _get_connection(env)
    if mode == 'u':
        bids = conn.get_all_spot_instance_requests()
        tags = dict([r.instance_id, r.tags] for r in bids)
        for i in env.instances:
            name = tags.get(i.id, {}).get('Name')
            if name:
                i.add_tag('Name', name)
    else:
        if mode == 'a':
            max_ind = _get_max_index(conn, typ)
        elif mode == 'w':
            max_ind = -1
        else:
            abort('Invalid tag mode. Should be one of u, a or w')
        for i in env.instances:
            max_ind += 1
            i.add_tag('Name', _encode_nodename(typ, max_ind))
    _print_instances(env.instances)


@task
def up(typ, count, bid=None):
    conn = _get_connection(env)
    max_ind = _get_max_index(conn, typ)
    groups = filter(None, env.group.split(',')) or None

    if bid is not None:
        results = conn.request_spot_instances(
            image_id=env.image,
            price=bid,
            count=int(count),
            key_name=env.key_pair,
            security_groups=groups,
            instance_type=env.instance,
            placement=env.get('zone'),
            subnet_id=env.get('subnet'))
        printer = _print_bid_requests
    else:
        reservation = conn.run_instances(
            image_id=env.image,
            min_count=int(count),
            max_count=int(count),
            key_name=env.key_pair,
            security_groups=groups,
            instance_type=env.instance,
            placement=env.get('zone'),
            subnet_id=env.get('subnet'))
        results = reservation.instances
        printer = _print_instances

    max_ind = _get_max_index(conn, typ)
    for r in results:
        max_ind += 1
        r.add_tag('Name', _encode_nodename(typ, max_ind))
    printer(results)


@task
def down():
    for i in env.instances:
        i.terminate()
    _print_instances(env.instances)


@task
def bids(state=None, status=None, action=None):
    conn = _get_connection(env)
    requests = conn.get_all_spot_instance_requests()
    if state:
        requests = filter(lambda r: r.state == state, requests)
    if status:
        requests = filter(lambda r: r.status.code == status, requests)
    env.bids = requests
    if action == 'cancel':
        for r in requests:
            r.cancel()
    _print_bid_requests(requests)


@task
@roles('worker')
@parallel
def remote(cmd, bg=None):
    (_to_bool(bg) and bgsudo or sudo)(cmd)


@task
@roles('worker')
@parallel
def install(*componets, **kwargs):
    for comp in componets:
        if comp == 'init':
            sudo('apt-get update && apt-get upgrade -yq && apt-get install -yq build-essential python-dev python python-pip python-virtualenv exim4')
            sudo('pip install -U pip')
            # sudo('DEBIAN_FRONTEND=noninteractive apt-get install -yq postfix')
            sed('/etc/exim4/update-exim4.conf.conf', 'local', 'internet', use_sudo=True)
            sudo('service exim4 restart || service exim4 start')
        else:
            execute(comp, 'install', **kwargs)


@task
@roles('worker')
@parallel
def update(*componets, **kwargs):
    for comp in componets:
        execute(comp, 'update', **kwargs)


@task
@roles('worker')
@parallel
def nginx(cmd):
    if cmd == 'install':
        sudo('apt-get update && apt-get install -yq nginx')
    elif cmd == 'update':
        sudo('mkdir -p /data/nginx')
        _put_file('_etc_nginx_nginx.conf')
        _put_file('_etc_security_limits.conf')
        sudo('mkdir -p /data/nginx && chown -R www-data:www-data /data/nginx')
        sudo('service nginx restart || service nginx start')
    elif cmd == 'start':
        sudo('service nginx start')
    elif cmd == 'restart':
        sudo('service nginx restart')
    else:
        sudo('nginx ' + cmd)


@task
@roles('worker')
@parallel
def sysctl(cmd):
    if cmd == 'update':
        _put_file('_etc_sysctl.conf')
        sudo('sysctl -p')
        _put_file('_etc_security_limits.conf')
    else:
        sudo('sysctl ' + cmd)


@task
@roles('worker')
@parallel
def dumper(cmd, bucket='thescore-tracker-east'):
    if cmd == 'install':
        sudo('apt-get install -yq s3cmd lzop inotify-tools')
        _put_file('_root_.s3cfg')
        sed('/root/.s3cfg', 'DUMPER_AWS_KEY', env.dumper_aws_key, use_sudo=True)
        sed('/root/.s3cfg', 'DUMPER_AWS_SECRET', env.dumper_aws_secret, use_sudo=True)
    elif cmd == 'update':
        sudo('mkdir -p /data/tracker/raw')
        sudo('mkdir -p /data/tracker/success')
        sudo('mkdir -p /data/tracker/fail')
        sudo('mkdir -p /data/dumper')
        _put_file('_opt_tracker_crontab')
        _put_file('_opt_tracker_dump.sh')
        sed('/opt/tracker/dump.sh', 'NODE_NAME', _node_name(), use_sudo=True)
        sed('/opt/tracker/dump.sh', 'S3_BUCKET_NAME', bucket, use_sudo=True)
        sudo('chmod +x /opt/tracker/dump.sh')
        with settings(warn_only=True):
            sudo('crontab -r')
        sudo('crontab /opt/tracker/crontab')
    else:
        abort('Invalid command.')


@task
@roles('worker')
@parallel
def monit(cmd):
    if cmd == 'install':
        sudo('apt-get update && apt-get install -yq monit')
    elif cmd == 'update':
        _put_file('_etc_monit_monitrc')
        sudo('chmod 600 /etc/monit/monitrc')
        sudo('monit reload || monit')
    else:
        sudo('monit ' + cmd)


##########################################
# manage locusts
##########################################
def _build_locust_cmd(params):
    options = ''
    for k, v in params.items():
        options += ' {}{} {}'.format(len(k) == 1 and ' -' or ' --', k, v)
    return 'locust ' + options


@task
@roles('worker')
@parallel
def locust(cmd, sync=None, **params):
    # target = params.pop('target', '54.174.127.47')
    target = params.pop('target', '54.165.24.62')
    node_name = _node_name()
    sync = _to_bool(sync)
    params.setdefault('f', '/opt/locust/locustfile.py')
    if not sync:
        params.setdefault('logfile', '/opt/locust/{}.locust.log'.format(node_name))
    if cmd == 'install':
        sudo('pip install -U pip  locustio')
    elif cmd == 'update':
        sudo('sysctl net.ipv4.tcp_tw_recycle=1')  # http://stackoverflow.com/questions/410616/increasing-the-maximum-number-of-tcp-ip-connections-in-linux
        sudo('sysctl net.ipv4.tcp_tw_reuse=1')
        _put_file('_opt_locust_locustfile.py')
        sed('/opt/locust/locustfile.py', 'NODE_NAME', node_name, use_sudo=True)
        sed('/opt/locust/locustfile.py', 'TRACKER_SERVER_IP', target, use_sudo=True)
    elif cmd == 'run':
        (sync and sudo or bgsudo)(_build_locust_cmd(params))
    elif cmd == 'master':
        params['master'] = ''
        params.pop('slave', None)
        params.setdefault('port', '80')
        (sync and sudo or bgsudo)(_build_locust_cmd(params))
    elif cmd == 'slave':
        params['slave'] = ''
        params.pop('master', None)
        params.setdefault('master-host', '54.86.218.120')
        (sync and sudo or bgsudo)(_build_locust_cmd(params))
    elif cmd == 'kill':
        sudo('kill -9 `pgrep locust`')
    elif cmd == 'clear':
        with settings(warn_only=True):
            sudo('rm -rf /opt/locust/*.locust.log')
    else:
        abort('Invalid command.')


@task
def reloc(master='f'):
    if _to_bool(master):
        execute('nodes', 'master')
        with settings(warn_only=True):
            execute('locust', 'kill')
            execute('locust', 'update')
            execute('locust', 'master')
    execute('nodes', 'slave')
    with settings(warn_only=True):
        execute('locust', 'kill')
    execute('locust', 'update')
    execute('locust', 'slave')
    execute('locust', 'slave')
    execute('locust', 'slave')
    execute('locust', 'slave')


@task
# @roles('worker')
# @parallel
def upload():
    put('localdata/sample.gz', '/home/ubuntu', use_sudo=True)
    with settings(warn_only=True):
        sudo('rm /home/ubuntu/sample')
    sudo('gzip -d /home/ubuntu/sample.gz')
    # sudo('mv /home/ubuntu/sample /home/ubuntu/sample.big')
    # sudo('head -n 2048 /home/ubuntu/sample.big > /home/ubuntu/sample')


##########################################
# handle the test results
##########################################
@task
@roles('worker')
@parallel
def gather(name):
    folder = 'localdata/' + name
    with settings(warn_only=True):
        local('rm rf ' + folder)
    local('mkdir -p ' + folder)
    with settings(warn_only=True):
        if exists('/data/tracker'):
            get('/data/tracker/*', folder)
        if exists('/media/locust'):
            get('/media/locust/*', folder)


@task
@roles('worker')
@parallel
def clear():
    with settings(warn_only=True):
        sudo('rm -rf /opt/locust/*')


def _parse_haproxy_log(line):
    try:
        ts, ip, req = line.split('|', 2)
        comps = req.split('/')
        slave = comps[1]
        value = int(comps[4])
        return [slave, float(ts), value]
    except:
        pass


@task
def report(name, reset=False):
    folder = os.path.join(here, 'localdata/' + name)
    hacsv = os.path.join(folder, 'export-haproxy.csv')
    lccsv = os.path.join(folder, 'export-locust.csv')

    if reset or not os.path.isfile(hacsv):
        with open(os.path.join(folder, 'haproxy-http.log'), 'r') as inp:
            results = []
            for l in inp:
                r = _parse_haproxy_log(l)
                if r:
                    results.append(r)
            ha = pd.DataFrame(results, columns=['slave', 'ts', 'value'])
            ha.to_csv(hacsv, index=True, header=False, delimiter=',')
    else:
        ha = pd.read_csv(hacsv, names=['slave', 'ts', 'value'], index_col=0)
    ha['ts'] = pd.to_datetime(ha['ts'], unit='s')

    if reset or not os.path.isfile(lccsv):
        results = []
        for filename in os.listdir(folder):
            if re.match('^locust_\d{3}_\d+$', filename):
                slave = filename.rsplit('_', 1)[0]
                with open(os.path.join(folder, filename), 'r') as inp:
                    for l in inp:
                        try:
                            ts, val = l.split()
                            results.append([slave, float(ts), int(val)])
                        except:
                            pass
        lc = pd.DataFrame(results, columns=['slave', 'ts', 'value'])
        lc.to_csv(lccsv, index=True, header=False, delimiter=',')
    else:
        lc = pd.read_csv(lccsv, names=['slave', 'ts', 'value'], index_col=0)
    lc['ts'] = pd.to_datetime(lc['ts'], unit='s')


##########################################
# haproxy log is not a ideal solution
##########################################

@task
@roles('worker')
@parallel
def haproxy(cmd):
    if cmd == 'install':
        sudo('add-apt-repository -y ppa:vbernat/haproxy-1.6 && apt-get update && apt-get install -yq haproxy')
        sudo('mkdir -p /var/log/haproxy')
        _put_file('_etc_haproxy_haproxy.cfg')
        _put_file('_etc_haproxy_errors_200.http')
        sudo('service haproxy restart || service haproxy start')
    elif cmd == 'update':
        _put_file('_etc_haproxy_haproxy.cfg')
        _put_file('_etc_haproxy_errors_200.http')
        sudo('service haproxy restart || service haproxy start')
    elif cmd == 'start':
        sudo('service haproxy start')
    elif cmd == 'restart':
        sudo('service haproxy restart')
    else:
        abort('Invalid command.')


@task
@roles('worker')
@parallel
def rsyslog(cmd):
    if cmd == 'install':
        with settings(warn_only=True):
            sudo('rm -f /etc/rsyslog.d/49-haproxy.conf')
        sudo('add-apt-repository -y ppa:adiscon/v8-stable && apt-get update && apt-get install -yq rsyslog')
        _put_file('_etc_rsyslog.d_49-haproxy.conf')
        sudo('service haproxy restart || service haproxy start')
    elif cmd == 'update':
        sudo('mkdir -p /data/tracker')
        sudo('chown -R syslog:adm /data/tracker')
        _put_file('_etc_rsyslog.d_49-haproxy.conf')
        sudo('service rsyslog restart || service rsyslog start')
    elif cmd == 'start':
        sudo('service rsyslog start')
    elif cmd == 'restart':
        sudo('service rsyslog restart')
    else:
        abort('Invalid command.')


##########################################
# maybe worth to try later
##########################################
@task
@roles('worker')
@parallel
def openresty(cmd):
    if cmd == 'install':
        sudo('apt-get install -yq libreadline-dev libncurses5-dev libpcre3-dev libssl-dev perl make build-essential')
        sudo('wget https://openresty.org/download/ngx_openresty-1.9.7.2.tar.gz')
        sudo('tar xvf ngx_openresty-1.9.7.2.tar.gz')
        with cd('ngx_openresty-1.9.7.2'):
            sudo('./configure --with-luajit --with-http_iconv_module -j2')
            sudo('./make')
            sudo('./make-install')
        sudo('mkdir -p /etc/openresty')
        sudo('mkdir -p /var/log/openresty')
        _put_file('_etc_openresty_openresty.conf')
        _put_file('_etc_openresty_server.lua')
        sudo('/usr/local/openresty/nginx/sbin/nginx -p /etc/openresty -c /etc/openresty/openresty.conf || /usr/local/openresty/nginx/sbin/nginx -p /etc/openresty -c /etc/openresty/openresty.conf -s reload')
    elif cmd == 'update':
        _put_file('_etc_openresty.conf')
        sudo('/usr/local/openresty/nginx/sbin/nginx -p /etc/openresty -c /etc/openresty/openresty.conf -s reload || /usr/local/openresty/nginx/sbin/nginx -p /etc/openresty -c /etc/openresty/openresty.conf')
    elif cmd == 'start':
        sudo('/usr/local/openresty/nginx/sbin/nginx -p /etc/openresty -c /etc/openresty/openresty.conf')
    elif cmd == 'restart':
        sudo('/usr/local/openresty/nginx/sbin/nginx -p /etc/openresty -c /etc/openresty/openresty.conf -s reload')
    else:
        abort('Invalid command.')


@task
@roles('worker')
@parallel
def uwsgi(cmd):
    if cmd == 'install':
        _put_file('_etc_init_uwsgi-emperor.conf')
        sudo('pip install uwsgi')
        sudo('mkdir -p /etc/uwsgi')
    elif cmd == 'update':
        _put_file('_etc_init_uwsgi-emperor.conf')
        sudo('service uwsgi-emperor restart || service uwsgi-emperor start')
    elif cmd == 'start':
        sudo('service uwsgi-emperor start')
    elif cmd == 'restart':
        sudo('service uwsgi-emperor restart')
    else:
        abort('Invalid command.')


@task
@roles('worker')
@parallel
def nodejs(cmd):
    if cmd == 'install':
        sudo('curl -sL https://deb.nodesource.com/setup_5.x | sudo -E bash -')
        sudo('apt-get install -yq nodejs')
    elif cmd == 'update':
        pass
    elif cmd == 'start':
        pass
    elif cmd == 'restart':
        pass
    else:
        abort('Invalid command.')
