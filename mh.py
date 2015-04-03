#!/usr/bin/env python
# -*- coding: utf-8 -*-
import signal
import os
import sys
import json
import re
import Queue
import pexpect
import threading
import logging
import pprint
import time
import multiprocessing
import commands

STR_PROMPT = 'propro>> '

STR_SETPROMPT = {
    'csh'  : "set prompt='%s'" % STR_PROMPT ,
    'tcsh' : "set prompt='%s'" % STR_PROMPT , 
    'bash' : "PS1='%s'" % STR_PROMPT,
    'sh'   : "PS1='%s'" % STR_PROMPT,
}

STR_UNALIAS = {
    'csh'  : r"unalias l. ll ls",
    'tcsh'  : r"unalias l. ll ls",
    'bash'  : r"unalias l. ll ls",
    'sh'  : r"unalias l. ll ls"
}


def parse_url(strings):
    parsed_dict={}
    regx=re.compile(r'^([^:]+)://([^/\s]+)$')
    regx_at=re.compile(r'^([^@]+)@([^@\s]+)$')
    regx_colon=re.compile(r'^([^:]+):([^:\s]+)$')
    
    rslt_cmd_dest=regx.search(strings)
    if not rslt_cmd_dest:
        return None

    parsed_dict={ 'cmd':rslt_cmd_dest.group(1), 'host':rslt_cmd_dest.group(2) }

    rslt_auth_dest=regx_at.search(parsed_dict['host'])
    if rslt_auth_dest:
        parsed_dict['user']=rslt_auth_dest.group(1)
        parsed_dict['host']=rslt_auth_dest.group(2)
        rslt_user_pass=regx_colon.search(parsed_dict['user'])
        if rslt_user_pass:
            parsed_dict['user']=rslt_user_pass.group(1)
            parsed_dict['password']=rslt_user_pass.group(2)

    rslt_host_port=regx_colon.search(parsed_dict['host'])
    if rslt_host_port:
        parsed_dict['host']=rslt_host_port.group(1)
        parsed_dict['port']=rslt_host_port.group(2)

    return parsed_dict

class RecursiveAuthCmd(object):
    def __init__(self,prefix,auths,command,root_timeout):
        self.logger=logging.getLogger("{0} {1}".format(self.__class__.__name__,prefix))
        self.prefix=prefix
        self.child=None
        self.timeout=root_timeout
        self.exits=[] 
        if len(auths) > 0: 
            self.recursiveAuth(auths)

    def exit(self):
        if len(self.exits) > 0:
            self.recursiveExit()


    def recursiveAuth(self,auths):
        self.logger.debug("{0},{1},{2}".format("auths",len(auths),pprint.pformat(auths).replace('\n',"{0}{1}".format('\\','\n'.encode('hex')))))
        auth=auths.pop(0)
        self.logger.debug("{0},{1}".format("auth",pprint.pformat(auth).replace('\n',"{0}{1}".format('\\','\n'.encode('hex')))))
        if not self.child:
            if auth['cmd'] == 'su':
                self.child = pexpect.spawn("su - {0}".format(auth['user']),timeout=self.timeout)
            elif auth['cmd'] == 'ssh':
                if not 'port' in auth: auth['port']=22
                if 'user'in auth: 
                    self.child = pexpect.spawn("ssh -l {0} -p {1} {2}".format(auth['user'],auth['port'],auth['host']),timeout=self.timeout) 
                else:
                    self.child = pexpect.spawn("ssh -p {0} {1}".format(auth['port'],auth['host']),timeout=self.timeout)
        else:
            if auth['cmd'] == 'su':
                self.child.sendline("su - {0}".format(auth['user']))
            elif auth['cmd'] == 'ssh':
                if not 'port' in auth: auth['port']=22
                if 'user'in auth:
                    self.child.sendline("ssh -l {0} -p {1} {2}".format(auth['user'],auth['port'],auth['host']))
                else:
                    self.child.sendline("ssh -p {0} {1}".format(auth['port'],auth['host']))
        i = self.child.expect(['assword: ','\(yes/no\)\?',r'@@@@@@@@','[#\$%] \Z'], timeout=self.timeout)
        self.logger.debug('{0}{1}'.format(self.child.before,self.child.after))
        if   i == 0:
            self.logger.debug('trying to enter password {0} as {1}'.format(auth['password'],auth['user']))
            self.child.sendline(auth['password'])
            self.child.expect ('[#\$%]', timeout=self.timeout)
        elif i == 1:
            self.child.sendline('yes')
            self.child.expect ('assword: ')
            self.logger.debug("{0}={1}".format(auth['password'],''.join(['%x ' % ord(s) for s in auth['password']])))
            
            self.child.sendline(auth['password'])
            self.child.expect ('[#\$%]', timeout=self.timeout)
        elif i == 2:
            print '\n !!!!!!!!!! Error:  please confirm ~/.ssh/known_hosts'
            self.exit()
        elif i == 3:
            pass 
        self.child.sendline('echo ${SHELL}')
        self.child.expect('/([^\r\n/]+/){0,}(?P<str_shell>[^\r\n/]+)[\r\n]+',timeout=self.timeout)
        self.shell = self.child.match.group('str_shell')
        self.child.sendline(STR_UNALIAS[self.shell])
        self.child.expect('[\r\n]+' ,timeout=self.timeout)
        self.child.sendline(STR_SETPROMPT[self.shell])
        self.child.expect('(([^\w\']*)%s\Z|^[^\r\n]+[\r\n]+)' % STR_PROMPT ,timeout=self.timeout)
        self.child.expect('%s' % STR_PROMPT ,timeout=self.timeout)
       
        self.exits.append(auth['cmd'])
        if len(auths) > 0:
            return self.recursiveAuth(auths)

    def recursiveExit(self):
        self.logger.debug("{0},{1},{2}".format("self.exits",len(self.exits),pprint.pformat(self.exits).replace('\n',"{0}{1}".format('\\','\n'.encode('hex')))))
        exit=self.exits.pop()
        self.logger.debug("{0},{1}".format("self.exits.pop()",pprint.pformat(exit).replace('\n',"{0}{1}".format('\\','\n'.encode('hex')))))
        if exit == 'su' or  exit == 'ssh':
            self.child.sendline('exit')
        if len(self.exits) > 0:
            return self.recursiveExit()
        else:
            self.child.expect(pexpect.EOF,self.timeout)
            self.child.close(self.timeout)

    def cmd(self,cmd,timeout=None):
        if timeout:
            cmd_timeout=timeout 
        else:
            cmd_timeout=self.timeout
        self.child.sendline(cmd)
        flag_gotprompt = False
        while not flag_gotprompt:
            try:
                i = self.child.expect(['[\r\n]+',STR_PROMPT+'\Z',pexpect.EOF] ,cmd_timeout)
            except ValueError,e:
                self.child.close()
                self.logger.error(pprint.pformat(e).replace('\n',"{0}{1}".format('\\','\n'.encode('hex'))))
                return False
                
            if i == 0 :
                self.output()
            elif i == 1 :
                flag_gotprompt = True
            elif i == 2 :
                self.child.close()
                self.output()
                return False 
        return True

    def output(self):
        print re.sub('^', '{0} '.format(self.prefix), '{0}{1}'.format(self.child.before,self.child.after) ),



class RemoteShellWorker(multiprocessing.Process):
    def __init__(self,id,que,que_done):
        self.logger=logging.getLogger(self.__class__.__name__)
        self.que=que
        self.que_done=que_done
        self.id=id
        multiprocessing.Process.__init__(self)

    def run(self):
        while True:
            try:
                taskname,task,cmd,my_timeout = self.que.get(timeout=1)
                r_auth_cmd=RecursiveAuthCmd(taskname,task,"ls",my_timeout)
                if r_auth_cmd.cmd(cmd,timeout=my_timeout):
                    r_auth_cmd.exit()
                for auth in task:
                    self.logger.debug("tid={0},{1}".format(self.id,pprint.pformat(auth).replace('\n',"{0}{1}".format('\\','\n'.encode('hex')))))
                self.que.task_done()
            except Queue.Empty:
                time.sleep(1)
                if self.que_done.value :
                    break
        return


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-D', '--Debug', action='store_const', const=logging.DEBUG, dest='loglevel')
    parser.add_argument('-P', '--Parallel', action='store_true')
    parser.add_argument('-N', '--Numthreads', default=1, type=int)
    parser.add_argument('-T', '--Timeout', default=3, type=int)
    parser.add_argument('command')
    method_group = parser.add_argument_group('method')
    method_group.add_argument('-p', '--prefix')
    method_group.add_argument('-m', '--methods', nargs='*', help='<cmd>://[<user>[:<pass>]@]<destination>[:<port>] cmd=(ssh | su) Ex. ssh://user@hostname.com')
    file_group = parser.add_argument_group('file')
    file_group.add_argument('-F', '--File', default='mh.cfg')
    file_group.add_argument('-f', '--file')
    file_group.add_argument('-t', '--target', nargs='*', default='ALL')

    args = parser.parse_args()

    logging.basicConfig(level=args.loglevel, format="%(asctime)s %(name)s %(levelname)s %(message)s" )
    logger=logging.getLogger(__name__)
    logger.debug(args)

    parsed_arg_methods=[]
    if args.methods:
        for method in args.methods:
            parsed_url=parse_url(method)
            if not parsed_url:
                logger.error('argument {0} is not able to be parse'.format(method) )
                exit(1)
            parsed_arg_methods.append(parsed_url)


    task_list={}

    if args.methods:
        if args.prefix:
            task_list[args.prefix]=parsed_arg_methods
        else:
            task_list['{0}@{1}'.format(parsed_arg_methods[-1]['user'],parsed_arg_methods[-1]['host'])]=parsed_arg_methods
    else:
        with open(args.File, 'r') as json_data:
            data = json.load(json_data)
            for session in data:
                task_list[session]=data[session]

    task_que=multiprocessing.JoinableQueue()
    task_que_done = multiprocessing.Value('b', False)

    worker_threads=[]
    for i in range(args.Numthreads):
        worker_threads.append(RemoteShellWorker(i,task_que,task_que_done))
        worker_threads[i].start()

    actual_target_list = []
    if args.file:
        with open(args.file) as f:
            for raw_line in f:
                line = raw_line.rstrip()
                if not line.startswith("\#"):
                    actual_target_list.append(line)
    else:
        if args.target == 'ALL':
            actual_target_list = task_list.keys()
        else:
            actual_target_list = args.target

    for task in task_list:
        logger.debug("Putting to Queue {0}".format(pprint.pformat(task).replace('\n',"{0}{1}".format('\\','\n'.encode('hex')))))
        if task in actual_target_list:
            task_que.put((task,task_list[task],args.command,args.Timeout))

    task_que.join()
    task_que.close()

    task_que_done.value = True
    for t in worker_threads:
        t.join()


if "__main__" == __name__:

    main()

