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

pyobjs_vtype_64 = { #Found info here: https://github.com/python/cpython/blob/2.7/Include/
    '_PyStringObject': [
        37,
        {
            'ob_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'ob_type': [8, ['pointer', ['void']]],  # struct _typeobject *
            'ob_size': [16, ['long long']],  # Py_ssize_t = ssize_t
            'ob_shash': [24, ['long long']],
            'ob_sstate': [32, ['Enumeration',
                               dict(target='int', choices={
                                   0: 'SSTATE_NOT_INTERNED',
                                   1: 'SSTATE_INTERNED_MORTAL',
                                   2: 'SSTATE_INTERNED_IMMORTAL'
                               })]],
            'ob_sval': [36, ['array', 1, ['char']]]
        }],
    '_PyUnicodeObject': [
        48,
        {
            'ob_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'ob_type': [8, ['pointer', ['void']]],  # struct _typeobject *
            'length': [16, ['long long']],  # Py_ssize_t = ssize_t
            'uni_str': [24, ['pointer', ['void']]],
            'shash': [32, ['long long']],
            'defenc': [40, ['pointer', ['_PyStringObject']]]
        }],
    '_PyDictEntry': [
        24,
        {
            'me_hash': [0, ['long long']],  # Py_ssize_t = ssize_t
            'me_key': [8, ['pointer', ['_PyStringObject']]],
            'me_value': [16, ['pointer', ['void']]]
        }],
    '_PyDictObject': [
        48,
        {
            'ob_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'ob_type': [8, ['pointer', ['void']]],  # struct _typeobject *
            'ma_fill': [16, ['long long']],  # Py_ssize_t = ssize_t
            'ma_used': [24, ['long long']],  # Py_ssize_t = ssize_t
            'ma_mask': [32, ['long long']],  # Py_ssize_t = ssize_t
            'ma_table': [40, ['pointer', ['_PyDictEntry']]]
        }],
    '_PyClassObject': [
        40,
        {
            'ob_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'ob_type': [8, ['pointer', ['void']]],  # struct _typeobject *
            'cl_bases': [16, ['pointer', ['void']]],  #Points to the class object
            'cl_dict': [24, ['pointer', ['_PyDictObject']]],
            'cl_name': [32, ['pointer', ['_PyStringObject']]]
        }],
    '_PyInstanceObject': [
        40,
        {
            'ob_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'ob_type': [8, ['pointer', ['void']]],  # struct _typeobject *
            'in_class': [16, ['pointer', ['_PyClassObject']]],  #Points to an instance object
            'in_dict': [24, ['pointer', ['_PyDictObject']]],
            'in_weakreflist': [32, ['pointer', ['void']]]
        }],
    '_PyFloatObject': [
        24,
        {
            'ob_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'ob_type': [8, ['pointer', ['void']]],  # struct _typeobject *
            'ob_fval': [16, ['long long']]  #double ob_fval //will convert later
        }],
    '_PyTupleObject': [
        32,
        {
            'ob_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'ob_type': [8, ['pointer', ['void']]],  # struct _typeobject *
            'ob_size': [16, ['long long']],  # Py_ssize_t = ssize_t
            'ob_item': [24, ['pointer', ['void']]]
        }],
    '_PyIntObject': [
        32,
        {
            'ob_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'ob_type': [8, ['pointer', ['void']]],  # struct _typeobject *
            'ob_ival': [16, ['long long']]
        }],
    '_PyBoolObject': [
        32,
        {
            'ob_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'ob_type': [8, ['pointer', ['void']]],  # struct _typeobject *
            'ob_ival': [16, ['long long']]
        }],
    '_PyListObject': [
        40,
        {
            'ob_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'ob_type': [8, ['pointer', ['void']]],  # struct _typeobject *
            'ob_size': [16, ['long long']],  # Py_ssize_t = ssize_t
            'ob_item': [24, ['pointer', ['void']]],
            'allocated': [32, ['long long']]
        }],
    '_PointerObj': [
        8,
        {
            'ob_ptr': [0, ['pointer', ['void']]]
        }]
    }


class _PyStringObject(obj.CType):
    r"""
    A class for python string objects.

    ----
    stringobject.h
    ----

    typedef struct {
        PyObject_VAR_HEAD
        long ob_shash;
        int ob_sstate;
        char ob_sval[1];

        /* Invariants:
         *     ob_sval contains space for 'ob_size+1' elements.
         *     ob_sval[ob_size] == 0.
         *     ob_shash is the hash of the string or -1 if not computed yet.
         *     ob_sstate != 0 iff the string object is in stringobject.c's
         *       'interned' dictionary; in this case the two references
         *       from 'interned' to this object are *not counted* in
         *       ob_refcnt.
         */
    } PyStringObject;

    #define SSTATE_NOT_INTERNED 0
    #define SSTATE_INTERNED_MORTAL 1
    #define SSTATE_INTERNED_IMMORTAL 2

    ----
    object.h - note that _PyObject_HEAD_EXTRA is empty if
    Py_TRACE_REFs is not defined
    ----

    /* PyObject_HEAD defines the initial segment of every PyObject. */
    #define PyObject_HEAD                   \
        _PyObject_HEAD_EXTRA                \
        Py_ssize_t ob_refcnt;               \
        struct _typeobject *ob_type;

    #define PyObject_VAR_HEAD               \
        PyObject_HEAD                       \
        Py_ssize_t ob_size; /* Number of items in variable part */

    """
    def is_valid(self):
        """
        Determine whether the Python string struct is valid - an easy way to
        check is to calculate the hash of the string, and see if it matches
        the `ob_shash`.

        On Python 2.7, the hash function used is FNV.

        This assumes that the python version volatility is using matches the
        python version of the memory dump, because it uses the `hash()`
        function to compute the hash.
        """
        ob_sval_offset, _ = self.members['ob_sval']
        string_address = self.obj_offset + ob_sval_offset
        return (
            self.ob_type.is_valid() and
            # skip empty strings and strings that are too big
            self.ob_size > 0 and self.ob_size <= 1e6 and
            # state must be one of the valid states
            self.ob_sstate.v() in self.ob_sstate.choices.keys() and
            # the string should be null-terminated
            self.obj_vm.zread(string_address + self.ob_size, 1) == '\x00' and
            # the hash may not have been computed (-1), but otherwise
            # it should be correct
            (self.ob_shash == -1 or self.ob_shash == hash(self.string)))

    @property
    def string(self):
        """
        Read the string from memory, because `ob_sval` is a
        :class:`volatility.obj.NativeType.Array` object, which is slow to
        iterate through to turn into a string.
        """
        sval_offset, _ = self.members['ob_sval']
        if (self.ob_size == 0):
            return ""
        else:
            return self.obj_vm.zread(self.obj_offset + sval_offset,
                                 self.ob_size)


class _PyUnicodeObject(obj.CType):
    r"""
    A class for python unicode string objects.

    typedef struct {
        PyObject_HEAD
        Py_ssize_t length;        /* Length of raw Unicode data in buffer */
        Py_UNICODE *str;          /* Raw Unicode buffer */
        long hash;                /* Hash value; -1 if not set */
        PyObject *defenc;         /* (Default) Encoded version as Python
                                    string, or NULL; this is used for
                                    implementing the buffer protocol */
    } PyUnicodeObject;
    """
    def is_valid(self):
        uni_buff = self.obj_vm.zread(self.uni_str, self.length * 4)
        return (
            self.ob_type.is_valid() and self.uni_str.is_valid() and
            self.length >= 0 and self.length <= 1e3 and 
            (self.shash == -1 or self.shash == hash(uni_buff.decode("utf-32"))))

    @property
    def string(self):
        if (self.length == 0):
            return "".decode("utf-32")
        else:
            uni_buff = self.obj_vm.zread(self.uni_str, self.length * 4)
            return uni_buff.decode("utf-32")


class _PyDictEntry(obj.CType):
    r"""
    ----
    dictobject.h
    ----

    typedef struct {
        Py_ssize_t me_hash;
        PyObject *me_key;
        PyObject *me_value;
    } PyDictEntry;

    ----
    object.h
    ----
    """
    def is_valid(self):
        """
        Determine whether the {Python string key: Python string val}
        PyDictEntry struct is valid.

        Both pointers should be valid, and the hash of the entry should be
        the same as the hash of the key.
        """
        if self.me_key.is_valid() and self.me_value.is_valid():
            key = self.key
            if key.is_valid() and key.ob_shash == self.me_hash:
                return True
        return False

    @property
    def key(self):
        return self.me_key.dereference()


class _PyDictObject(obj.CType):
    r"""
    ----
    dictobject.h
    ----

    typedef struct _dictobject PyDictObject;
    struct _dictobject {
        PyObject_HEAD
        Py_ssize_t ma_fill;  /* # Active + # Dummy */
        Py_ssize_t ma_used;  /* # Active */

        /* The table contains ma_mask + 1 slots, and that's a power of 2.
        * We store the mask instead of the size because the mask is more
        * frequently needed.
        */
        Py_ssize_t ma_mask;

        /* ma_table points to ma_smalltable for small tables, else to
        * additional malloc'ed memory.  ma_table is never NULL!  This rule
        * saves repeated runtime null-tests in the workhorse getitem and
        * setitem calls.
        */
        PyDictEntry *ma_table;
        PyDictEntry *(*ma_lookup)(PyDictObject *mp, PyObject *key, long hash);
        PyDictEntry ma_smalltable[PyDict_MINSIZE];
    };
    """
    def is_valid(self):
        """
        Determine if the dict structure is valid by checking if ma_used is less 
        than ma_fill and if ma_mask + 1 is a power of 2.
        """
        return (self.ob_type.is_valid() and 
            self.ma_fill >= self.ma_used and self.ma_mask > 0 and 
            ((self.ma_mask + 1) & self.ma_mask) == 0)


class _PyClassObject(obj.CType):
    def is_valid(self):
        """
        Determine whether the Python class is valid
        """
        if self.ob_type.is_valid() and self.cl_name.is_valid() and self.cl_dict.is_valid():
            found_string = self.cl_name.dereference()
            found_dict = self.cl_dict.dereference() #Dog dict ma_fill = 4, ma_used = 4, ma_mask = 7
            if found_string.is_valid() and found_dict.is_valid():
                return True
        return False


    @property
    def name(self):
        class_string = self.cl_name.dereference()
        return class_string.string


class _PyInstanceObject(obj.CType): #change
    def is_valid(self):
        """
        Determine whether the Python instance is valid
        """
        if self.ob_type.is_valid() and self.in_class.is_valid() and self.in_dict.is_valid():
            found_class = self.in_class.dereference()
            found_dict = self.in_dict.dereference()
            if found_class.is_valid() and found_dict.is_valid():
                return True
        return False
        #found_object = obj.Object("_PyClassObject",
        #                          offset=self.in_class,
        #                          vm=addr_space)
        #return found_object.is_valid(addr_space, name)

    @property
    def name(self):
        found_class = self.in_class.dereference()
        return found_class.name


class _PyFloatObject(obj.CType):
    def is_valid(self):
        return self.ob_type.is_valid()

    @property
    def val(self):
        return float(ctypes.c_double.from_buffer(ctypes.c_longlong(self.ob_fval)).value)


class _PyTupleObject(obj.CType):
    def is_valid(self):
        if self.ob_type.is_valid() == False or self.ob_size <= 0 or self.ob_size > 5:
            return False
        ptr_offset, _ = self.members['ob_item']
        
        for i in range(self.ob_size):
            tmp_ptr = obj.Object("_PointerObj",
                            offset=self.obj_offset + ptr_offset + 8 * i,
                            vm=self.obj_vm)
            if tmp_ptr.is_valid() == False:
                return False
        return True
    
    @property
    def val(self):
        ptr_offset, _ = self.members['ob_item']
        ptrs = []
        for i in range(self.ob_size):
            tmp_ptr = obj.Object("_PointerObj",
                            offset=self.obj_offset + ptr_offset + 8 * i,
                            vm=self.obj_vm)
            ptrs.append(tmp_ptr.val)
        return ptrs


class _PyIntObject(obj.CType):
    def is_valid(self):
        return self.ob_type.is_valid() and self.ob_ival.is_valid()

    @property
    def val(self):
        return int(self.ob_ival)


class _PyBoolObject(obj.CType):
    def is_valid(self):
        return self.ob_type.is_valid() and self.ob_ival.is_valid()

    @property
    def val(self):
        return self.ob_ival != 0


class _PyListObject(obj.CType):
    def is_valid(self):
        if self.ob_type.is_valid() == False or self.ob_item.is_valid() == False:
            return False
        if self.ob_size <= 0 or self.ob_size > 500 or self.allocated < self.ob_size:
            return False
        curr = self.ob_item
        end = self.ob_item + (self.allocated - 1) * 8
        ct = 0
        while (curr <= end):
            tmp_ptr = obj.Object("_PointerObj",
                            offset=curr,
                            vm=self.obj_vm)
            if tmp_ptr.is_valid():
                ct += 1
                if ct == self.ob_size:
                    return True
            curr += 8
        return False
    
    @property
    def val(self):
        ptrs = []
        curr = self.ob_item
        end = self.ob_item + (self.allocated - 1) * 8
        ct = 0
        while (curr <= end):
            tmp_ptr = obj.Object("_PointerObj",
                            offset=curr,
                            vm=self.obj_vm)
            if tmp_ptr.is_valid():
                ct += 1
                ptrs.append(tmp_ptr.val)
                if ct == self.ob_size:
                    return ptrs
            curr += 8


class _PointerObj(obj.CType):
    def is_valid(self):
        return self.ob_ptr.is_valid()
    
    @property
    def val(self):
        return self.ob_ptr


class PythonClassTypes(obj.ProfileModification):
    """
    Profile modifications for Python class types.  Only Linux and Mac OS,
    on 64-bit systems, are supported right now.
    """
    conditions = {"os": lambda x: x in ["linux", "mac"],
                  "memory_model": lambda x: x == "64bit"}

    def modification(self, profile):
        profile.vtypes.update(pyobjs_vtype_64)
        profile.object_classes.update({
            "_PyStringObject": _PyStringObject,
            "_PyUnicodeObject": _PyUnicodeObject,
            "_PyDictEntry": _PyDictEntry,
            "_PyDictObject": _PyDictObject,
            "_PyClassObject": _PyClassObject,
            "_PyInstanceObject": _PyInstanceObject,
            "_PyFloatObject": _PyFloatObject,
            "_PyTupleObject": _PyTupleObject,
            "_PyIntObject": _PyIntObject,
            "_PyBoolObject": _PyBoolObject,
            "_PyListObject": _PyListObject,
            "_PointerObj": _PointerObj
        })


def get_entry(type_info, ptr, addr_space):
    entry_type = type_info[0]
    l = []

    tmp_entry = obj.Object(entry_type,
                            offset=ptr,
                            vm=addr_space)

    if ((entry_type == "_PyStringObject" and tmp_entry.ob_size > 0 and tmp_entry.is_valid() == False) 
        or (entry_type != "_PyStringObject" and tmp_entry.is_valid() == False)):
        print "uh oh, entry invalid", entry_type 
    
    if entry_type == "_PyTupleObject":
        ptr_list1 = tmp_entry.val
        if (len(ptr_list1) != len(type_info[1])):
            print "unequal ptr list lens", len(ptr_list1), len(type_info[1])
            sys.exit(0)
        for i in range(len(type_info[1])):
            if type(type_info[1][i]) is not list:
                l += [get_entry([type_info[1][i]], ptr_list1[i], addr_space)]
            else:
                l += [get_entry(type_info[1][i], ptr_list1[i], addr_space)]
        return tuple(l)
    elif entry_type == "_PyListObject":
        ptr_list2 = tmp_entry.val
        if (len(ptr_list2) != len(type_info[1])):
            print "unequal ptr list lens", len(ptr_list2), len(type_info[1])
            sys.exit(0)
        for i in range(len(type_info[1])):
            if type(type_info[1][i]) is not list:
                l += [get_entry([type_info[1][i]], ptr_list2[i], addr_space)]
            else:
                l += [get_entry(type_info[1][i], ptr_list2[i], addr_space)]
        return l
    elif entry_type == "_PyStringObject":
        return tmp_entry.string
    elif entry_type == "_PyUnicodeObject":
        return tmp_entry.string
    else:
        return tmp_entry.val


def dig_dicts(dict_obj, task): 
    addr_space = task.get_process_address_space()
    DICT_TYPES = { #SPECIFIC TO CARLA HUD OBJECT __DICT__
        "dim": ["_PyTupleObject", ["_PyIntObject", "_PyIntObject"]],
        #"_notifications": _PyInstanceObject,
        #"help": _PyInstanceObject,
        #"_server_clock": 
        "frame": ["_PyIntObject"],
        "simulation_time": ["_PyFloatObject"],
        "server_fps": ["_PyFloatObject"],
        "_show_info": ["_PyBoolObject"],
        "_info_text": ["_PyListObject", ['_PyStringObject', '_PyStringObject', '_PyStringObject', 
                                        '_PyStringObject', '_PyStringObject', '_PyStringObject', 
                                        '_PyStringObject', '_PyStringObject', '_PyUnicodeObject', 
                                        '_PyStringObject', '_PyStringObject', '_PyStringObject', 
                                        '_PyStringObject', '_PyStringObject', '_PyStringObject', 
                                        ['_PyTupleObject', ['_PyStringObject', '_PyFloatObject', 
                                        '_PyFloatObject', '_PyFloatObject']], ['_PyTupleObject', 
                                        ['_PyStringObject', '_PyFloatObject', '_PyFloatObject', 
                                        '_PyFloatObject']], ['_PyTupleObject', ['_PyStringObject', 
                                        '_PyFloatObject', '_PyFloatObject', '_PyFloatObject']], 
                                        ['_PyTupleObject', ['_PyStringObject', '_PyBoolObject']], 
                                        ['_PyTupleObject', ['_PyStringObject', '_PyBoolObject']], 
                                        ['_PyTupleObject', ['_PyStringObject', '_PyBoolObject']], 
                                        '_PyStringObject', '_PyStringObject', '_PyStringObject', 
                                        ['_PyListObject', ['_PyFloatObject', '_PyFloatObject', 
                                        '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject', '_PyFloatObject']], 
                                        '_PyStringObject', '_PyStringObject']

                        ]
    }

    ret = {}
    slots = dict_obj.ma_mask + 1
    offset = dict_obj.ma_table
    end = dict_obj.ma_table + 24 * slots
    #print "offset, smalltab", offset, 40 + dict_obj.obj_offset + 16 #ma_table points to small table for dog obj
    while offset <= end:
        entry = obj.Object("_PyDictEntry",
                            offset=offset,
                            vm=addr_space)
        if entry.is_valid():
            if entry.key.string in DICT_TYPES:
                tmp = get_entry(DICT_TYPES[entry.key.string], entry.me_value, addr_space)
                ret.update({entry.key.string: tmp}) 
        offset += 24

    return str(ret)

def brute_force_search(addr_space, obj_type_string, start, end, step_size, class_name):
    """
    Brute-force search an area of memory for a given object type.  Returns
    valid types as a generator.
    """
    offset = start
    while offset < end:
        found_object = obj.Object(obj_type_string,
                                  offset=offset,
                                  vm=addr_space)
        if found_object.is_valid() and found_object.name == class_name:
            yield found_object
            offset += found_object.size()
        else:
            offset += step_size


def find_instance(task, class_name):
    """
    Attempt to find all python instance __dict__'s thbrough a brute-force search.
    """
    addr_space = task.get_process_address_space()
    heaps = get_heaps_and_anon(task)
    found_instances = []
    chunk_size = 1024 * 5

    for heap_vma in heaps:
        for chunk_start in xrange(heap_vma.vm_start,
                                  heap_vma.vm_end,
                                  chunk_size):
            found_instances.extend(list(brute_force_search(
                addr_space=addr_space,
                obj_type_string="_PyInstanceObject",
                start=chunk_start,
                end=chunk_start + chunk_size - 1,
                step_size=1,
                class_name = class_name)))
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
    Checks if the task has the CARLA PID
    """
    if str(task.pid) != pidstr:
        return False
    else:
        return True


class linux_find_instances2(linux_pslist.linux_pslist):
    """
    Pull instance objects from a process's heap.
    """
    def __init__(self, config, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
        self._config.add_option(
            'PID', short_option = 'p', default = None,
                          help = 'Operate on the CARLA Process ID',
                          action = 'store', type = 'str')

    def _validate_config(self):
        if self._config.PID is not None and len(self._config.PID.split(',')) != 1:
            debug.error("Please enter the CARLA Python API process PID")
        
    def calculate(self):
        """
        Find the tasks that are actually python processes.  May not
        necessarily be called "python", but the executable is python.

        """
        #start = timeit.default_timer()

        linux_common.set_plugin_members(self)
        self._validate_config()
        pidstr = self._config.PID
        class_name = "HUD"

        tasks = []
        for task in linux_pslist.linux_pslist.calculate(self):
            if _is_python_task(task, pidstr):
                tasks.append(task)

        for task in tasks:
            for instance in find_instance(task, class_name):
                yield instance, dig_dicts(instance.in_dict.dereference(), task)
        
        #stop = timeit.default_timer()
        #print("Runtime: {0}".format(stop - start))

    def unified_output(self, data):
        """
        Return a TreeGrid with data to print out.
        """
        return TreeGrid([("Name", str),
                         ("Dict", str)],
                        self.generator(data))

    def generator(self, data):
        """
        Generate data that may be formatted for printing.
        """
        for instance, tmp_dict in data:
            yield (0, [str(instance.name),
                       str(tmp_dict)])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Name", "10"),
                                  ("Dict", "2000")])
        for _, output in self.generator(data):
            self.table_row(outfd, *[str(o) for o in output])
