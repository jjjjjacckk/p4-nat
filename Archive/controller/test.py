#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
import random
import threading
from time import sleep
import inspect

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../utils/'))
import p4runtime_lib.bmv2
# from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
from p4.v1 import p4runtime_pb2
import p4runtime_lib.helper


p4info_helper = p4runtime_lib.helper.P4InfoHelper('../build/simple_router_16.p4.p4info.txt')
a = p4info_helper.get_tables_name(33610441)
print a

