# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

def options(opt):
    opt.load(['compiler_c', 'compiler_cxx'])

def configure(conf):
    conf.load(['compiler_c', 'compiler_cxx'])
    conf.check_cfg(package='libndn-cxx', args=['--cflags', '--libs'], uselib_store='NDN_CXX', mandatory=True)
    conf.check_cfg(path='pcap-config', package='libpcap', args=['--libs', '--cflags'], uselib_store='PCAP', mandatory=True)

def build(bld): # 创建一个任务生成器，用来生成下面的任务
    bld.program(
        features='cxx',
        target='server',
        source=bld.path.ant_glob(['src/*.cpp', 'src/consumer/*.cpp']),
        includes = ". ./src/ ./src/consumer", 
        use='NDN_CXX PCAP',
    )
