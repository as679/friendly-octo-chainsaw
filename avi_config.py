#!/usr/bin/env python
import argparse
import json
import sys
import requests
import urllib3
urllib3.disable_warnings()

operations = ['serviceenginegroup', 'pool', 'networkprofile', 'analyticsprofile', 'applicationprofile', 'wafprofile', 'wafpolicy']

def create(config, prefix, member, session, baseuri):
  for op in operations:
    config[op]['name'] = "%s-%s" % (prefix, op)
    if op == 'serviceenginegroup':
      config[op]['se_name_prefix'] = prefix
    elif op == 'pool':
      config[op]['servers'][0]['ip']['addr'] = member
      hm = session.get(baseuri + 'api/healthmonitor/?name=System-HTTP&fields=url')
      hm.raise_for_status()
      hm = hm.json()
      try:
        config[op]['health_monitor_refs'].append(hm['results'][0]['url'])
      except IndexError as err:
        print err
        sys.exit(1)
    elif op == 'wafpolicy':
      config[op]['waf_profile_ref'] = config['wafprofile']['response']['url']
    response = session.post(baseuri + 'api/' + op, json=config[op])
    try:
      response.raise_for_status()
    except:
      print "ERROR: Creating %s: %s" % (op, response.text)
      rollback = []
      for i in operations:
        if i == op:
          break
        else:
          rollback.append(i)
      for rollback in reversed(rollback):
        print "Rollback: %s" % rollback
        session.delete(config[rollback]['response']['url'])
      sys.exit(1)
    config[op]['response'] = response.json()
    print "Created %s: %s" % (op, config[op]['response']['uuid'])

def delete(config, session):
  for op in reversed(operations):
    try:
      response = session.delete(config[op]['response']['url'])
      response.raise_for_status()
      print "Deleted %s: %s" % (op, config[op]['response']['uuid'])
    except:
      print "ERROR: Deleting %s: %s" % (op, response.text)

def sub_element(element, report, session):
  if isinstance(element, dict):
    for k, v in element.items():
      if k.endswith('_ref'):
        response = session.get(v)
        response.raise_for_status()
        report[k] = response.json()
        sub_element(report[k], report, session)
      elif isinstance(v, dict):
        sub_element(v, report, session)
      elif isinstance(v, list):
        for i in v:
            sub_element(i, report, session)
  elif isinstance(element, list):
    for i in element:
      sub_element(i, report, session)

def report(vs_name, session, baseuri):
  report = {'avi_reference': {}}
  response = session.get(baseuri + 'api/virtualservice/?name=%s' % vs_name)
  response.raise_for_status()
  if response.json()['count'] == 1:
    vs = response.json()['results'][0]
    report['virtual_service'] = vs
    sub_element(vs, report['avi_reference'], session)
  else:
    print "ERROR: virtual service %s not found" % vs_name
    sys.exit(1)
  return report

def write_output(config, output):
  print "Writing output to file: %s" % output
  with open(output, 'w') as fh:
    json.dump(config, fh)

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('--ctrl', help='controller to connect to')
  parser.add_argument('--username', help='usernamae to authenticate as', default='admin')
  parser.add_argument('--password', help='password for username')
  parser.add_argument('--json', help='configuration file', default='config.json')
  parser.add_argument('--outjson', help='configuration output file', default='config.json.output')
  parser.add_argument('--prefix', help='naming prefix for created objects', default='AviLAB')
  parser.add_argument('--op', help='what to do', default='create')
  parser.add_argument('--member', help='new member IP address', default='127.0.0.1')
  parser.add_argument('--virtual_service', help='virtua service name to report on')
  args = parser.parse_args()

  uri = "https://%s/" % args.ctrl

  try:
    with open(args.json) as fh:
      cfg = json.load(fh)
  except IOError as err:
    print err
    sys.exit(1)

  s = requests.session()
  s.verify = False
  s.post(uri + 'login', data={'username':args.username,'password':args.password}).raise_for_status()
  s.headers.update({'X-Avi-Version':'17.2.9','Referer':uri,'X-CSRFToken':s.cookies['csrftoken']})

  if args.op == 'create':
    if args.member == '127.0.0.1':
      print "WARNING: You may want to add a valid member IP address for the pool..."
    try:
      with open(args.json) as fh:
        cfg = json.load(fh)
    except IOError as err:
      print err
      sys.exit(1)
    create(cfg, args.prefix, args.member, s, uri)
    write_output(cfg, args.json + '.output')
  elif args.op == 'delete':
    try:
      with open(args.outjson) as fh:
        cfg = json.load(fh)
    except IOError as err:
      print err
      sys.exit(1)
    delete(cfg, s)
  elif args.op == 'report':
    if not args.virtual_service:
      print "ERROR: Need to supply virtual service name"
      sys.exit(1)
    write_output(report(args.virtual_service, s, uri), args.outjson)

if __name__ == '__main__':
  main()
