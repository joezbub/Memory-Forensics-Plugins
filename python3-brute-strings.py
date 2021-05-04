import ctypes
import os
import re
import struct
import sys
import time
import timeit

from itertools import groupby

import volatility.debug as debug
import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
from volatility.plugins.linux import pslist as linux_pslist
from volatility.renderers import TreeGrid
from volatility import utils

pyobjs_vtype_64 = { #Found info here: https://github.com/python/cpython/blob/3.7/Include
    '_PyTypeObject': [
        40,
        {
            'ob_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'ob_type': [8, ['pointer', ['void']]],  # struct _typeobject *
            'ob_size': [16, ['long long']],  # Py_ssize_t = ssize_t
            'tp_name': [24, ['pointer', ['char']]],
            'tp_basicsize': [32, ['long long']]
        }],
    '_PyUnicodeString': [ #PyUnicodeObject already used?
        80,
        {
            'ob_refcnt': [0, ['long long']],
            'ob_type': [8, ['pointer', ['_PyTypeObject']]],  
            'length': [16, ['long long']],  # number of code points
            'ob_hash': [24, ['long long']],
            'ob_state': [32, ['unsigned int']], #interned 0-2, kind 1 2 4, compact 0-1, ascii 0-1, ready 0-1
            'ob_wstr': [36, ['pointer', ['void']]],
            'alignment1': [44, ['void']],
            'utf8_length': [48, ['long long']],
            'utf8_ptr': [56, ['pointer', ['char']]],
            'wstr_length': [64, ['long long']],
            'ob_data': [72, ['pointer', ['char']]]
        }]
    }


class _PyTypeObject(obj.CType):
    def is_valid(self):
        if not (self.ob_type.is_valid() and self.tp_name.is_valid() and self.tp_basicsize.is_valid()):
            return False
        s = "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM._-\/"
        for i in range(41):
            tmp = self.obj_vm.zread(self.tp_name + i, 1)
            if tmp == '\0':
                if (i >= 2):
                    return True
                else:
                    return False
            if tmp not in s:
                return False
        return False

    @property
    def name(self):
        ct = 0
        s = "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM._-\/"
        for i in range(41):
            tmp = self.obj_vm.zread(self.tp_name + i, 1)
            if tmp == '\0' or tmp not in s:
                ct = i
                break
        ret = str(self.obj_vm.zread(self.tp_name, ct))
        return ret

class _PyUnicodeString(obj.CType):
    def is_valid(self): #ob_hash is different from Python's builtin hash
        if not (self.ob_type.is_valid() and self.ob_type.dereference().is_valid()
                and self.length > 0 and self.length <= 1e2 and self.ob_hash.is_valid()
                and "str" in self.ob_type.dereference().name
                and self.ob_type.dereference().tp_basicsize == 80):
            return False

        interned = kind = compact = ascii_tmp = ready = -1

        if (self.ob_state >> 1) & 1 and not((self.ob_state >> 0) & 1): #interned
            interned = 2
        elif not(self.ob_state >> 1) & 1 and (self.ob_state >> 0) & 1:
            interned = 1
        elif not(self.ob_state >> 1) & 1 and not((self.ob_state >> 0) & 1):
            interned = 0

        if (self.ob_state >> 4) & 1: #kind
            if not((self.ob_state >> 3) & 1) and not((self.ob_state >> 2) & 1):
                kind = 4
        else:
            if ((self.ob_state >> 3) & 1) and not((self.ob_state >> 2) & 1):
                kind = 2
            elif not((self.ob_state >> 3) & 1) and ((self.ob_state >> 2) & 1):
                kind = 1
            elif not((self.ob_state >> 3) & 1) and not((self.ob_state >> 2) & 1):
                kind = 0
        
        compact = int(((self.ob_state >> 5) & 1))
        ascii_tmp = int(((self.ob_state >> 6) & 1))
        ready = int(((self.ob_state >> 7) & 1))
        
        if interned == -1 or kind <= 0 or compact <= 0 or ascii_tmp <= 0 or ready <= 0: 
            #ignore ready legacy or unready legacy or compact unicode
            return False

        if (kind > 1):
            print interned, kind, compact, ascii_tmp, ready
        
        if ascii_tmp == 1:
            return True
        elif ascii_tmp == 0:
            print self.utf8_length, self.length, self.wstr_length, kind
            print hex(self.utf8_ptr), hex(self.ob_data)
            print hex(tmp_long)
            return True


    @property
    def val(self):
        interned = kind = compact = ascii_tmp = ready = 0
        if (self.ob_state >> 1) & 1 and not((self.ob_state >> 0) & 1): #interned
            interned = 2
        elif not(self.ob_state >> 1) & 1 and (self.ob_state >> 0) & 1:
            interned = 1
        elif not(self.ob_state >> 1) & 1 and not((self.ob_state >> 0) & 1):
            interned = 0

        if (self.ob_state >> 4) & 1: #kind
            if not((self.ob_state >> 3) & 1) and not((self.ob_state >> 2) & 1):
                kind = 4
        else:
            if ((self.ob_state >> 3) & 1) and not((self.ob_state >> 2) & 1):
                kind = 2
            elif not((self.ob_state >> 3) & 1) and ((self.ob_state >> 2) & 1):
                kind = 1
            elif not((self.ob_state >> 3) & 1) and not((self.ob_state >> 2) & 1):
                kind = 0
        
        compact = int(((self.ob_state >> 5) & 1))
        ascii_tmp = int(((self.ob_state >> 6) & 1))
        ready = int(((self.ob_state >> 7) & 1))
        
        if ascii_tmp == 1:
            uni_buff = self.obj_vm.zread(self.obj_offset + 48, self.length)
            return uni_buff
        elif ascii_tmp == 0:
            uni_buff = self.obj_vm.zread(self.obj_offset + 72, self.length)
            print uni_buff.encode("utf-8")
            return uni_buff.decode()


class PythonClassTypes3(obj.ProfileModification):
    """
    Profile modifications for Python class types.  Only Linux and Mac OS,
    on 64-bit systems, are supported right now.
    """
    conditions = {"os": lambda x: x in ["linux", "mac"],
                  "memory_model": lambda x: x == "64bit"}

    def modification(self, profile):
        profile.vtypes.update(pyobjs_vtype_64)
        profile.object_classes.update({
            "_PyTypeObject": _PyTypeObject,
            "_PyUnicodeString": _PyUnicodeString
        })


def brute_force_search(addr_space, obj_type_string, start, end, step_size):
    """
    Brute-force search an area of memory for a given object type.  Returns
    valid types as a generator.
    """
    offset = start
    arr = []
    while offset < end:
        found_object = obj.Object(obj_type_string,
                                  offset=offset,
                                  vm=addr_space)
        
        if found_object.is_valid():
            arr.append(found_object)
            offset += 48 + found_object.length
        else:
            offset += step_size
    return arr


def find_instance(task):
    addr_space = task.get_process_address_space() #5603 seconds
    heaps = get_heaps_and_anon(task)
    
    found_instances = []
    for heap_vma in heaps:
        found_instances.extend(brute_force_search(
                addr_space=addr_space,
                obj_type_string="_PyUnicodeString",
                start=heap_vma.vm_start,
                end=heap_vma.vm_end,
                step_size=1))
    return found_instances


def get_heaps_and_anon(task):
    """
    Given a task, return the mapped sections corresponding to that task's
    heaps and anonymous mappings (since CPython sometimes mmaps things).
    """
    for vma in task.get_proc_maps():
        if (vma.vm_start <= task.mm.start_brk and vma.vm_end >= task.mm.brk):
            yield vma
        elif vma.vm_name(task) == "Anonymous Mapping":
            yield vma


def _is_python_task(task, pidstr):
    """
    Checks if the task has the Python PID
    """
    if str(task.pid) != pidstr:
        return False
    else:
        return True


class linux_python3_strings(linux_pslist.linux_pslist):
    """
    Pull instance objects from a process's heap.
    """
    def __init__(self, config, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
        self._config.add_option(
            'PID', short_option = 'p', default = None,
                          help = 'Operate on the Python PID',
                          action = 'store', type = 'str')

    def _validate_config(self):
        if self._config.PID is not None and len(self._config.PID.split(',')) != 1:
            debug.error("Please enter the Python PID")
        
    def calculate(self):
        """
        Find the tasks that are actually python processes.  May not
        necessarily be called "python", but the executable is python.

        """
        start = timeit.default_timer()
        linux_common.set_plugin_members(self)

        self._validate_config()
        pidstr = self._config.PID

        tasks = []
        for task in linux_pslist.linux_pslist.calculate(self):
            if _is_python_task(task, pidstr):
                tasks.append(task)

        for task in tasks:
            for string in find_instance(task):
                yield string
        
        #stop = timeit.default_timer()
        #print("Runtime: {0}".format(stop - start))

    def unified_output(self, data):
        """
        Return a TreeGrid with data to print out.
        """
        return TreeGrid([("Name", str)],
                        self.generator(data))

    def generator(self, data):
        """
        Generate data that may be formatted for printing.
        """
        for instance in data:
            yield (0, [str(instance.val)])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Name", "100")])
        for _, output in self.generator(data):
            self.table_row(outfd, *[str(o) for o in output])
