import ctypes
import os
import re
import struct
import sys
import time
import timeit
import io
import json
import random
from collections import OrderedDict

from itertools import groupby

import volatility.debug as debug
import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
from volatility.plugins.linux import pslist as linux_pslist
from volatility.renderers import TreeGrid
from volatility import utils

PROFILE_PATH = "./Scripts/ScriptOutputs/profile_py.txt"  # PATH TO PYTHON PROFILE
PROFILE_DATA = None
recovered_c_structs = 0
recovered_python_objects = 0
false_positives = 0
hyperparameters = 0

pyobjs_vtype_64 = { #Found info here: https://github.com/python/cpython/blob/3.6/Include
    'C_String': [
        1,
        {
            'buf': [0, ['char']]
        }],
    '_PyTypeObject': [
        400,
        {
            'ob_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'ob_type': [8, ['pointer', ['void']]],  # struct _typeobject *
            'ob_size': [16, ['long long']],  
            'tp_name': [24, ['pointer', ['C_String']]],
            'tp_basicsize': [32, ['long long']],
            'tp_itemsize': [40, ['long long']],
            'data1': [48, ['void']],
            'tp_dictoffset': [288, ['long long']],
            'data2': [296, ['void']]
        }],
    '_PyUnicodeString': [
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
        }],
    '_PyGC_Head': [
        24,
        {
            'gc_next': [0, ['unsigned long long']],
            'gc_prev': [8, ['unsigned long long']],
            'gc_refs': [16, ['long long']],
        }],
    '_GC_Runtime_State': [
        352,
        {
            'trash_delete_later': [0, ['address']],
            'trash_delete_nesting': [8, ['int']], 
            'enabled': [12, ['int']],
            'debug': [16, ['int']],
            'alignment1': [20, ['void']],
            'gen1_head': [32, ['_PyGC_Head']],
            'gen1_dummy': [56, ['void']],
            'gen1_threshold': [64, ['int']],
            'gen1_count': [68, ['int']],
            'gen1_alignment': [72, ['void']],
            'gen2_head': [80, ['_PyGC_Head']],
            'gen2_dummy': [104, ['void']],
            'gen2_threshold': [112, ['int']],
            'gen2_count': [116, ['int']],
            'gen1_alignment': [120, ['void']],
            'gen3_head': [128, ['_PyGC_Head']],
            'gen3_dummy': [152, ['void']],
            'gen3_threshold': [160, ['int']],
            'gen3_count': [164, ['int']],
            'gen1_alignment': [168, ['void']],
            'generation0': [176, ['pointer', ['_PyGC_Head']]],
            'alignment2': [184, ['void']],
            'perm_gen_head': [192, ['_PyGC_Head']],
            'perm_gen_dummy': [216, ['void']],
            'perm_gen_threshold': [224, ['int']],
            'perm_gen_count': [228, ['int']],
            'end_data': [232, ['void']]
        }],
    '_PyInterpreters': [
        32,
        {
            'interpreters_mutex': [0, ['address']],
            'interpreters_head': [8, ['address']], 
            'interpreters_main': [16, ['address']],
            'interpreters_next_id': [24, ['long long']],
        }],
    '_PyRuntimeState': [ 
        1520,
        {
            'initialized': [0, ['int']],
            'core_initialized': [4, ['int']],  
            'finalizing': [8, ['pointer', ['void']]], 
            'interpreters': [16, ['_PyInterpreters']],
            'exitfuncs': [48, ['void']],
            'nexitfuncs': [304, ['int']],
            'alignment1': [308, ['void']],
            'gc': [320, ['_GC_Runtime_State']],
            'end_data': [672, ['void']]
        }],
    '_PyDictKeyEntry1': [
        24,
        {
            'me_hash': [0, ['long long']],  # Py_ssize_t = ssize_t
            'me_key': [8, ['pointer', ['_PyUnicodeString']]],
            'me_value': [16, ['address']]
        }],
    '_PyDictKeysObject1': [
        48,
        {
            'dk_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'dk_size': [8, ['long long']],  # Py_ssize_t = ssize_t
            'dk_lookup': [16, ['pointer', ['void']]], 
            'dk_usable': [24, ['long long']], 
            'dk_nentries': [32, ['long long']],
            'dk_indices': [40, ['void']]
        }],
    '_PyDictObject1': [
        48,
        {
            'ob_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'ob_type': [8, ['pointer', ['_PyTypeObject']]],  # struct _typeobject *
            'ma_used': [16, ['long long']],  # number of items
            'ma_version_tag': [24, ['unsigned long long']], #unique identifier
            'ma_keys': [32, ['pointer', ['_PyDictKeysObject1']]], #PyDictKeysObject
            'ma_values': [40, ['pointer', ['void']]] #just values
        }],
    '_PyInstanceObject1': [
        32,
        {
            'ob_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'ob_type': [8, ['pointer', ['_PyTypeObject']]],  # struct _typeobject *
            'in_dict': [16, ['pointer', ['_PyDictObject1']]],  #Points to __dict__
            'data': [24, ['void']]
        }],
    '_PyFloatObject1': [
        24,
        {
            'ob_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'ob_type': [8, ['pointer', ['_PyTypeObject']]],  # struct _typeobject *
            'ob_fval': [16, ['long long']]  #double ob_fval //will convert later
        }],
    '_PyTupleObject1': [
        32,
        {
            'ob_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'ob_type': [8, ['pointer', ['_PyTypeObject']]],  # struct _typeobject *
            'ob_size': [16, ['long long']],  # Py_ssize_t = ssize_t
            'ob_item': [24, ['pointer', ['void']]]
        }],
    '_PyLongObject1': [
        32,
        {
            'ob_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'ob_type': [8, ['pointer', ['_PyTypeObject']]],  # struct _typeobject *
            'ob_size': [16, ['long long']],
            'ob_digit': [24, ['unsigned int']]
        }],
    '_PyListObject1': [
        40,
        {
            'ob_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'ob_type': [8, ['pointer', ['_PyTypeObject']]],  # struct _typeobject *
            'ob_size': [16, ['long long']],  # Py_ssize_t = ssize_t
            'ob_item': [24, ['pointer', ['void']]],
            'allocated': [32, ['long long']]
        }],
    '_PyBoolObject1': [
        32,
        {
            'ob_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'ob_type': [8, ['pointer', ['_PyTypeObject']]],  # struct _typeobject *
            'ob_size': [16, ['long long']],
            'ob_digit': [24, ['unsigned int']]
        }],
    '_PyEagerTensor1': [
        152,
        {
            'ob_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'ob_type': [8, ['pointer', ['_PyTypeObject']]],  # struct _typeobject *
            'unused': [16, ['void']],
            'handle': [80, ['pointer', ['_TensorHandle']]],
            'ob_id': [88, ['long long']],
            'is_packed': [96, ['long long']],
            'handle_data': [104, ['address']],
            'tensor_shape': [112, ['address']],
            'ob_status': [120, ['void']],
            'context': [128, ['address']],
            'weakreflist': [136, ['address']],
            'ob_dict': [144, ['_PyDictObject1']],
        }],
    '_TensorHandle': [
        336,
        {
            'vtable_ptr1': [0, ['address']],  # Py_ssize_t = ssize_t
            'vtable_ptr2': [8, ['address']],
            'dtype': [32, ['short']], #0x14
            'random_fields': [36, ['void']],
            'tensor_': [304, ['_Tensor1']]
        }],
    '_Iterator': [
        40,
        {
            'next': [0, ['pointer', ['_Iterator']]],
            'guard': [8, ['address']],
            'name': [16, ['pointer', ['C_String']]],
            'weird_int': [24, ['int']],
            'tensorflow_var': [32, ['pointer', ['_TensorflowVar']]]
        }],
    '_TensorflowVar': [
        72,
        {
            'vtable_ptr': [0, ['address']],
            'mutex': [8, ['void']],
            'tensor': [40, ['_Tensor1']]
        }],
    '_PyDimension1': [
        32,
        {
            'ob_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'ob_type': [8, ['pointer', ['_PyTypeObject']]],  # struct _typeobject *
            'ob_dim': [16, ['pointer', ['_PyLongObject1']]],
            'model_ptr': [24, ['pointer', ['void']]]
        }],
    '_TensorShape1': [
        32,
        {
            'ob_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'ob_type': [8, ['pointer', ['_PyTypeObject']]],  # struct _typeobject *
            'ob_list': [16, ['pointer', ['_PyListObject1']]]
        }],
    'float32': [
        4,
        {
            'ob_fval': [0, ['int']]
        }],
    '_ResourceHandleData': [
        24,
        {
            'context_str': [0, ['pointer', ['C_String']]],
            'device_name': [8, ['pointer', ['C_String']]],
            'var_name': [16, ['pointer', ['C_String']]]
        }],
    '_TensorBuffer1': [
        24,
        {
            'vtable_ptr': [0, ['pointer', ['address']]],  # ptr to vtable
            'ob_refcnt': [8, ['long long']],
            'data_': [16, ['pointer', ['float32']]]
        }],
    '_Tensor1': [
        32,
        {
            'shape': [0, ['array', 8, ['unsigned short int']]],  
            'num_elements': [16, ['long long']],
            'buf_': [24, ['pointer', ['_TensorBuffer1']]]
        }],
    '_WeakRef1': [
        24,
        {
            'ob_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'ob_type': [8, ['pointer', ['_PyTypeObject']]],  # struct _typeobject *
            'buf_': [16, ['address']]
        }],
    '_PyObject1': [
        16,
        {
            'ob_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'ob_type': [8, ['pointer', ['_PyTypeObject']]],  # struct _typeobject *
        }]
    }
    

class C_String(obj.CType):
    @property
    def val(self):
        ret = ""
        for i in range(150):
            tmp = self.obj_vm.zread(self.obj_offset + i, 1)
            if ord(tmp) == 0:
                if (i >= 2):
                    return ret
                else:
                    return "invalid"
            if ord(tmp) < 32 or ord(tmp) > 126:
                return "invalid"
            ret += tmp
        return "invalid"
    
    def is_valid(self):
        return self.buf.is_valid() and self.val != "invalid"


class _PyTypeObject(obj.CType):
    def is_valid(self):
        return self.ob_type.is_valid() and self.tp_name.dereference().is_valid() and self.tp_basicsize.is_valid()
        
    @property
    def name(self):
        return self.tp_name.dereference().val


class _PyUnicodeString(obj.CType):
    def parse_state(self):
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

        return interned, kind, compact, ascii_tmp, ready

    def is_valid(self): #ob_hash is different from Python's builtin hash
        if not (self.ob_type.is_valid() and self.ob_type.dereference().is_valid()
                and self.length > 0 and self.length <= 1e2 and self.ob_hash.is_valid()
                and self.ob_type.dereference().tp_basicsize == 80):
            return False

        interned, kind, compact, ascii_tmp, ready = self.parse_state()

        #ignore ready legacy or unready legacy or compact unicode
        if interned == -1 or kind <= 0 or compact <= 0 or ascii_tmp <= 0 or ready <= 0: 
            return False
        else:
            return True

    @property
    def val(self):
        interned, kind, compact, ascii_tmp, ready = self.parse_state()

        if ascii_tmp == 1: #should go here, never encountered compact unicode before
            uni_buff = self.obj_vm.zread(self.obj_offset + 48, self.length)
            return uni_buff
        elif ascii_tmp == 0: 
            uni_buff = self.obj_vm.zread(self.obj_offset + 72, self.length)
            print uni_buff.encode("utf-8")
            return uni_buff.decode()


class _PyGC_Head(obj.CType):
    def is_valid(self):
        return (self.gc_next.is_valid() and self.gc_prev.is_valid() and self.gc_refs.is_valid())

    @property
    def next_val(self):
        return self.gc_next

    @property
    def prev_val(self):
        return self.gc_prev
    

class _GC_Runtime_State(obj.CType):
    def is_valid(self):
        return (self.trash_delete_later.is_valid() and self.trash_delete_nesting.is_valid()
            and self.gen1_head.is_valid() and self.gen2_head.is_valid() and self.gen3_head.is_valid())


class _PyInterpreters(obj.CType):
    def is_valid(self):
        return (self.interpreters_mutex.is_valid() and self.interpreters_head.is_valid()
            and self.interpreters_main.is_valid())


class _PyRuntimeState(obj.CType):
    def is_valid(self):
        return (self.initialized.is_valid() and self.core_initialized.is_valid() 
            and self.interpreters.is_valid() and self.gc.is_valid())

    @property
    def gen1_next(self):
        return self.gc.gen1_head.next_val
    
    @property
    def gen2_next(self):
        return self.gc.gen2_head.next_val

    @property
    def gen3_next(self):
        return self.gc.gen3_head.next_val

    @property
    def gen1_prev(self):
        return self.gc.gen1_head.prev_val
    
    @property
    def gen2_prev(self):
        return self.gc.gen2_head.prev_val

    @property
    def gen3_prev(self):
        return self.gc.gen3_head.prev_val


class _PyDictKeyEntry1(obj.CType):
    def is_valid(self):
        """
        Key pointers should be valid and should point to a PyUnicodeString
        """
        return (self.me_key.is_valid() and self.me_key.dereference().is_valid())
            
    @property
    def key(self):
        return self.me_key.dereference().val
    
    @property
    def value(self):
        return self.me_value


class _PyDictKeysObject1(obj.CType):
    def get_entries_start(self):
        """
        Indices must be: 0 <= indice < USABLE_FRACTION(dk_size).
        The size in bytes of an indice depends on dk_size:
        - 1 byte if dk_size <= 0xff (char*)
        - 2 bytes if dk_size <= 0xffff (int16_t*)
        - 4 bytes if dk_size <= 0xffffffff (int32_t*)
        - 8 bytes otherwise (int64_t*)
        """
        indices_offset, _ = self.members['dk_indices']
        
        if (self.dk_size <= 0xff):
            ind_sz = 1
        elif (self.dk_size <= 0xffff):
            ind_sz = 2
        elif (self.dk_size <= 0xffffffff):
            ind_sz = 4
        else:
            ind_sz = 8
        return self.obj_offset + indices_offset + self.dk_size * ind_sz


    def is_valid(self):
        return (#address of lookup function
                self.dk_lookup.is_valid() 
                #dk_size is size of hash table (must be power of 2)
                and (self.dk_size & (self.dk_size - 1)) == 0)

    @property
    def val_combined(self):
        keys = []
        val_ptrs = []
        curr = self.get_entries_start()
        end = curr + (self.dk_nentries - 1) * 24
        ct = 0
        #print "this is a combined dict"
        while (curr <= end):
            tmp_ptr = obj.Object("_PyDictKeyEntry1",
                            offset=curr,
                            vm=self.obj_vm)
            ct += 1
            if tmp_ptr.is_valid():
                keys.append(tmp_ptr.key)
                val_ptrs.append(tmp_ptr.value)
                if ct == self.dk_nentries:
                    return keys, val_ptrs
            else:
                pass
                #print "oops"
            curr += 24
    
    @property
    def val_reg(self):
        keys = []
        val_ptrs = []
        curr = self.get_entries_start()
        end = curr + (self.dk_nentries - 1) * 24
        ct = 0
        #print "not combined"
        while (curr <= end):
            tmp_ptr = obj.Object("_PyDictKeyEntry1",
                            offset=curr,
                            vm=self.obj_vm)
            ct += 1
            if tmp_ptr.is_valid():
                keys.append(tmp_ptr.key)
                if ct == self.dk_nentries:
                    return keys
            else:
                pass
                #print "oops"
            curr += 24
    

class _PyDictObject1(obj.CType):
    def addr_to_obj(self, addr):
        tmp = obj.Object("_PyObject1",
                        offset=addr,
                        vm=self.obj_vm)
        return tmp.val

    def is_valid(self):
        return (self.ob_type.is_valid()
                and self.ma_used >= 0 and self.ma_keys.is_valid() 
                and self.ma_keys.dereference().is_valid()
                and (self.ma_values == 0 or self.ma_values.is_valid()))

    @property
    def values(self): #returns array of addresses of PyObjects
        ptrs = []
        ret = []
        curr = self.ma_values
        end = self.ma_values + (self.ma_used - 1) * 8
        ct = 0
        while (curr <= end):
            tmp_ptr = obj.Object("address",
                            offset=curr,
                            vm=self.obj_vm)
            if tmp_ptr.is_valid():
                ct += 1
                ptrs.append(tmp_ptr)
                if ct == self.ma_used:
                    break
            curr += 8
        for addr in ptrs:
            ret.append(self.addr_to_obj(addr))
        return ret

    @property
    def val(self):
        d = {}

        #combined
        if self.ma_keys.dereference().dk_refcnt == 1 and self.ma_values == 0:
            keys, values = self.ma_keys.dereference().val_combined
            for i in range(len(keys)):
                d[keys[i]] = self.addr_to_obj(values[i])

        #not combined       
        else: 
            keys = self.ma_keys.dereference().val_reg
            values = self.values
            for i in range(self.ma_used):
                d[keys[i]] = values[i]
        return d


class _PyInstanceObject1(obj.CType): 
    def is_valid(self):
        return (self.ob_type.is_valid() and self.ob_type.dereference().is_valid()
                and self.in_dict.is_valid() and self.in_dict.dereference().is_valid())
        
    @property
    def name(self):
        return self.ob_type.dereference().name
    
    @property
    def val(self):
        return self.in_dict.dereference().val


class _PyFloatObject1(obj.CType):
    def is_valid(self):
        return (self.ob_type.is_valid() and "float" in self.ob_type.dereference().name)

    @property
    def val(self):
        return float(ctypes.c_double.from_buffer(ctypes.c_longlong(self.ob_fval)).value)


class _PyTupleObject1(obj.CType):
    def addr_to_obj(self, addr):
        tmp = obj.Object("_PyObject1",
                        offset=addr,
                        vm=self.obj_vm)
        return tmp.val

    def is_valid(self):
        return (self.ob_type.is_valid() and "tuple" in self.ob_type.dereference().name)
    
    @property
    def val(self):
        ptr_offset, _ = self.members['ob_item']
        ptrs = []
        ret = []
        for i in range(self.ob_size):
            tmp_ptr = obj.Object("address",
                            offset=self.obj_offset + ptr_offset + 8 * i,
                            vm=self.obj_vm)
            ptrs.append(tmp_ptr)
        for addr in ptrs:
            ret.append(self.addr_to_obj(addr))
        return tuple(ret)


class _PyLongObject1(obj.CType): #unfinished
    """
    tp_itemsize = 4 #digits are unsigned ints
    /* Long integer representation.
    The absolute value of a number is equal to
            SUM(for i=0 through abs(ob_size)-1) ob_digit[i] * 2**(SHIFT*i)
    Negative numbers are represented with ob_size < 0;
    zero is represented by ob_size == 0.
    In a normalized number, ob_digit[abs(ob_size)-1] (the most significant
    digit) is never zero.  Also, in all cases, for all valid i,
            0 <= ob_digit[i] <= MASK.
    The allocation function takes care of allocating extra memory
    so that ob_digit[0] ... ob_digit[abs(ob_size)-1] are actually available.
    CAUTION:  Generic code manipulating subtypes of PyVarObject has to
    aware that ints abuse  ob_size's sign bit.
    */
    """
    def is_valid(self):
        return (self.ob_type.is_valid() and "int" in self.ob_type.dereference().name
                and self.ob_type.dereference().tp_basicsize == 24)

    @property
    def val(self):
        if self.ob_size == 0:
            return 0
        mult = self.ob_size / abs(self.ob_size)
        ret = 0

        indices_offset, _ = self.members['ob_digit']
        curr = self.obj_offset + indices_offset
        end = curr + 4 * (abs(self.ob_size) - 1)
        ct = 0
        while (curr <= end):
            tmp = obj.Object("unsigned int",
                            offset=curr,
                            vm=self.obj_vm)
            if tmp.is_valid():
                ret += (tmp * (2 ** (30 * ct)))
                ct += 1
                if ct == abs(self.ob_size):
                    return int(ret * mult)
            curr += 4


class _PyListObject1(obj.CType):
    def addr_to_obj(self, addr):
        tmp = obj.Object("_PyObject1",
                        offset=addr,
                        vm=self.obj_vm)
        return tmp.val

    def is_valid(self):
        """
        /* ob_item contains space for 'allocated' elements.  The number
        * currently in use is ob_size.
        * Invariants:
        *     0 <= ob_size <= allocated
        *     len(list) == ob_size
        *     ob_item == NULL implies ob_size == allocated == 0
        * list.sort() temporarily sets allocated to -1 to detect mutations.
        *
        * Items must normally not be NULL, except during construction when
        * the list is not yet visible outside the function that builds it.
        */
        """
        return (self.ob_type.is_valid() and self.ob_item.is_valid() 
                and "list" in self.ob_type.dereference().name 
                and self.ob_size <= self.allocated and self.ob_size > 0)
    
    @property
    def val(self):
        ptrs = []
        ret = []
        curr = self.ob_item
        end = self.ob_item + (self.allocated - 1) * 8
        ct = 0
        while (curr <= end):
            tmp_ptr = obj.Object("address",
                            offset=curr,
                            vm=self.obj_vm)
            if tmp_ptr.is_valid():
                ct += 1
                ptrs.append(tmp_ptr)
                if ct == self.ob_size:
                    break
            curr += 8
        for addr in ptrs:
            ret.append(self.addr_to_obj(addr))
        return ret


class _PyBoolObject1(obj.CType):
    def is_valid(self):
        return (self.ob_type.is_valid() and self.ob_type.dereference().is_valid()
                and "bool" in self.ob_type.dereference().name 
                and self.ob_type.dereference().tp_basicsize == 32)

    @property
    def val(self):
        return self.ob_digit != 0


class _PyEagerTensor1(obj.CType):
    def is_valid(self):
        return (self.ob_type.is_valid() and self.ob_type.dereference().is_valid()
                and self.ob_type.dereference().name == "tensorflow.python.framework.ops.EagerTensor"
                and self.ob_type.dereference().tp_basicsize == 152 and self.handle.dereference().is_valid())

    @property
    def val(self):
        return self.ob_digit != 0


class _TensorHandle(obj.CType):
    def is_valid(self):
        return (self.dtype == 14)


class _Iterator(obj.CType):
    def is_valid(self):
        return (self.guard != 0 and self.tensorflow_var.dereference().is_valid())

    @property
    def val(self):
        return self.name.dereference().val


class _TensorflowVar(obj.CType):
    def is_valid(self):
        return self.vtable_ptr.is_valid()

    @property
    def val(self):
        self.vtable_ptr


class _PyDimension1(obj.CType):
    def is_valid(self):
        return (self.ob_type.is_valid() and self.ob_type.dereference().is_valid()
                and "Dimension" in self.ob_type.dereference().name)

    @property
    def val(self):
        return self.ob_dim.dereference().val


class _TensorShape1(obj.CType):
    def is_valid(self):
        return (self.ob_type.is_valid() and self.ob_type.dereference().is_valid()
                and "TensorShape" in self.ob_type.dereference().name)

    @property
    def val(self):
        return self.ob_list.dereference().val


class float32(obj.CType):
    def is_valid(self):
        curr = self.val
        return isinstance(curr, float)

    @property
    def val(self):
        return float(ctypes.c_float.from_buffer(ctypes.c_int(self.ob_fval)).value)


class _ResourceHandleData(obj.CType):
    def is_valid(self):
        return ("device:CPU" in self.context_str.dereference().val 
            and "localhost" == self.device_name.dereference().val)

    @property
    def val(self):
        return self.var_name.dereference().val


class _TensorBuffer1(obj.CType):
    def is_valid(self):
        return (self.vtable_ptr.is_valid() and self.vtable_ptr.dereference().is_valid()  
                and self.ob_refcnt.is_valid() and self.data_.is_valid() and self.data_.dereference().is_valid())

    @property
    def val(self):
        return self.data_


class _Tensor1(obj.CType):
    def is_valid(self):
        return (self.num_elements.is_valid() and self.buf_.is_valid() 
                and self.buf_.dereference().is_valid())

    @property
    def val(self):
        return self.buf_.dereference().val


class _WeakRef1(obj.CType):
    def is_valid(self):
        return (self.ob_type.is_valid() and self.ob_type.dereference().is_valid()
                and self.ob_type.dereference().name == "weakref")
    
    @property
    def val(self):
        return self.buf_


class _PyObject1(obj.CType):
    def get_type(self, s):
        pymap = ({
            "dict": "_PyDictObject1",
            "collections.OrderedDict": "_PyDictObject1",
            "Tensor": "TorchParameter",
            "Parameter": "TorchParameter",
            "int": "_PyLongObject1",
            "str": "_PyUnicodeString",
            "float": "_PyFloatObject1",
            "list": "_PyListObject1",
            "bool": "_PyBoolObject1",
            "tuple": "_PyTupleObject1",
            "tensorflow.python.framework.ops.EagerTensor": "_PyEagerTensor1",
            "Dimension": "_PyDimension1",
            "TensorShape": "_TensorShape1",
            "weakref": "_WeakRef1"
        })
        if not pymap.has_key(s):
            return "_PyObject1"
        return pymap[s]

    def is_valid(self):
        return (self.ob_type.is_valid() and self.ob_type.dereference().is_valid())

    @property
    def val(self):
        obj_string = self.get_type(self.ob_type.dereference().name)
        if (self.ob_type.dereference().tp_basicsize == 32 
            and self.ob_type.dereference().tp_dictoffset == 16):
            obj_string = "_PyInstanceObject1"
        tmp = obj.Object(obj_string, offset=self.obj_offset, vm=self.obj_vm)
        if obj_string not in ["_PyEagerTensor1", "_PyInstanceObject1", "_PyObject1", "_PyDictObject1", "_TensorShape1", "TorchParameter"]:
            return tmp.val
        elif obj_string == "_PyObject1" and tmp.ob_type.dereference().name == "NoneType":
            return None
        else:
            return tmp


class PythonClassTypes4(obj.ProfileModification):
    """
    Profile modifications for Python class types.  Only Linux and Mac OS,
    on 64-bit systems, are supported right now.
    """
    conditions = {"os": lambda x: x in ["linux", "mac"],
                  "memory_model": lambda x: x == "64bit"}
    
    def modification(self, profile):
        profile.vtypes.update(pyobjs_vtype_64)
        profile.object_classes.update({
            "C_String": C_String,
            "_PyTypeObject": _PyTypeObject,
            "_PyUnicodeString": _PyUnicodeString,
            "_PyGC_Head": _PyGC_Head,
            "_GC_Runtime_State": _GC_Runtime_State,
            "_PyInterpreters": _PyInterpreters,
            "_PyRuntimeState": _PyRuntimeState,
            "_PyDictKeyEntry1": _PyDictKeyEntry1,
            "_PyDictKeysObject1": _PyDictKeysObject1,
            "_PyDictObject1": _PyDictObject1,
            "_PyInstanceObject1": _PyInstanceObject1,
            "_PyFloatObject1": _PyFloatObject1,
            "_PyTupleObject1": _PyTupleObject1,
            "_PyLongObject1": _PyLongObject1,
            "_PyListObject1": _PyListObject1,
            "_PyBoolObject1": _PyBoolObject1,
            "_PyEagerTensor1": _PyEagerTensor1,
            "_TensorHandle": _TensorHandle,
            "_Iterator": _Iterator,
            "_TensorflowVar": _TensorflowVar,
            "_PyDimension1": _PyDimension1,
            "_TensorShape1": _TensorShape1,
            "float32": float32,
            "_ResourceHandleData": _ResourceHandleData,
            "_TensorBuffer1": _TensorBuffer1,
            "_Tensor1": _Tensor1,
            "_WeakRef1": _WeakRef1,
            "_PyObject1": _PyObject1
        })


def get_heaps(task):
    heaps = []
    for vma in task.get_proc_maps(): # get heaps
        if vma.vm_name(task) == "[heap]":
            heaps.append(vma)
    return heaps


def calc_tot(shape_list):
    tot_elements = 1
    for dim in shape_list:
        tot_elements *= dim
    return tot_elements


def extract_data(addr_space, num_elements, buf):
    ct = 0
    ret = []
    while (ct != num_elements):
        found_object = obj.Object("float32",
                                offset=buf,
                                vm=addr_space)
        if (ct < 3):
            print found_object.val
        if not isinstance(found_object.val, float): #invalid tensor
            return []
        else:
            ret.append(found_object.val)
        buf += 4
        ct += 1

    return ret


def is_tensor_valid(actual_name, tensor, shape_list, tot_elements):
    if not tensor.is_valid():
        return False

    if tensor.num_elements != tot_elements: 
        print "num_elements is wrong:", int(tensor.num_elements), tot_elements
        return False

    for i in range(len(shape_list)):
        if (shape_list[i] != int(tensor.shape[i])):
            print "shape is wrong"
            return False
    
    return True


def scan_heap(task, addr_space, shape, anonvar_to_name):
    """
    Searches process heap(s) for valid Iterator structs which will contain 
    tensorflow::Var with a mutex and Tensor. Extract floats from TensorBuffer.
    """
    heaps = get_heaps(task)
    weight_results = {}
    vis = set()
    tensor_offsets = {}

    global recovered_c_structs
    global false_positives

    for heap in heaps:
        tmp = heap.vm_end / 8 * 8  # make sure divisible by 8
        end = (heap.vm_start + 7) / 8 * 8
        print "from", hex(int(tmp)), "to", hex(int(end))
        
        while tmp != end and len(vis) < len(anonvar_to_name): # begin search
            
            found_object = obj.Object("_Iterator",
                            offset=tmp,
                            vm=addr_space)

            if found_object.is_valid() and found_object.val in anonvar_to_name and found_object.val not in vis:
                print "\nfound:", found_object.val, "at", hex(found_object.obj_offset)
                actual_name = anonvar_to_name[found_object.val]
                tensor = found_object.tensorflow_var.dereference().tensor
                shape_list = shape[actual_name]
                tot_elements = calc_tot(shape_list)
                recovered_c_structs += 4
                if is_tensor_valid(actual_name, tensor, shape_list, tot_elements):
                    print actual_name, "works"
                    print "num_elements", tensor.num_elements
                    print "obj_offset", hex(tensor.obj_offset)
                    print "vtable ptr:", hex(tensor.buf_.dereference().vtable_ptr)
                    print "data_ ptr:", hex(tensor.buf_.dereference().data_)
                    print len(anonvar_to_name) - len(vis) - 1, "left"
                    weight_results[actual_name] = extract_data(addr_space, tensor.num_elements, int(tensor.buf_.dereference().data_))
                    tensor_offsets[actual_name] = int(tensor.obj_offset)
                    vis.add(found_object.val)
                else:
                    false_positives += 1

            tmp -= 8

    print "\ndone with extraction\n"
    return weight_results, tensor_offsets


def extract_func_graph(addr_space, model_root):
    model_dict = model_root.in_dict.dereference().val

    global recovered_python_objects

    print model_dict['name']
    print (model_dict['_weak_variables'])
            
    layers_ordered = []
    for var in model_dict['_weak_variables']:
        tensor = obj.Object("_PyInstanceObject1",
                            offset=var,
                            vm=addr_space)
        recovered_python_objects += 1
        name = tensor.in_dict.dereference().val['_handle_name']
        layers_ordered.append({"_name": name, "_trainable_weights": [tensor], "_non_trainable_weights": []})
    return layers_ordered


def bfs(model_root):
    """
    Searches model tree and returns list of leaves in order
    """

    global recovered_python_objects

    layers_ordered = []
    queue = [model_root]
    while (len(queue)):
        node = queue.pop(0)
        node_dict = node.in_dict.dereference().val
        recovered_python_objects += 1
        if (len(node_dict['_layers']) == 0 or 
            len(node_dict['_trainable_weights']) > 0 or 
            len(node_dict['_non_trainable_weights']) > 0):
            layers_ordered.append(node_dict)
            continue
        for layer in node_dict['_layers']:
            recovered_python_objects += 1
            queue.append(layer)
    return layers_ordered


def get_anonvar(tensor_dict, addr_space):
    """might be wrong tho

    Returns variable name from Resource Handle Data
    """
    
    global recovered_c_structs
    global recovered_python_objects

    recovered_c_structs += 3
    recovered_python_objects += 1

    data_addr = tensor_dict['_handle'].handle.dereference().tensor_.buf_.dereference().data_
    tmp = obj.Object("_ResourceHandleData",
                            offset=data_addr,
                            vm=addr_space)
    anonvar = tmp.var_name.dereference().val
    return anonvar


def check_weights(task, out_dict):
    """
    Prints metrics about accuracy of weight recovery relative to ground truth
    """
    f = open("correct_weights_" + str(task.pid) + ".txt", "r")
    correct_dump = json.load(f)

    missing_weights = 0
    missing_layers = 0
    diff_weights = 0
    sum_diff = 0
    missing_arr = []
    diff_layers = []

    for layer in correct_dump['tensors']:
        if (layer in out_dict['tensors']):
            print (layer)
            
            correct_arr = correct_dump['tensors'][layer]
            recovered_arr = out_dict['tensors'][layer]

            diff_pos = []
            
            if (len(recovered_arr) != len(correct_arr)):
                print "Shapes Different"
            else:
                for i in range(len(correct_arr)):
                    if (recovered_arr[i] != correct_arr[i]):
                        diff_pos.append(i)

            if (len(diff_pos) == len(correct_arr)):
                print "No Valid Tensors"
            else:
                print("{} weights different".format(len(diff_pos)))
                print (diff_pos)
                sum_diff += len(diff_pos)
            if len(diff_pos) > 0:
                diff_layers.append(layer)
            print

        else:
            missing_layers += 1
            missing_weights += len(correct_dump['tensors'][layer])
            missing_arr.append(layer)

    print ("Correct model_name: {}".format(correct_dump['model_name']))
    print("Received model_name: {}".format(out_dict['model_name']))
    print ("Correct num_elements: {}".format(correct_dump['num_elements']))
    print ("Received num_elements: {}\n".format(out_dict['num_elements']))
    print (len(diff_layers))
    print (diff_layers)
    print (sum_diff)
    print ("{} layers not found".format(missing_layers))
    print (missing_arr)
    print ("{} out of {} found weights are different".format(sum_diff, correct_dump['num_elements'] - missing_weights))


def export_weights(task, weights, tot_num_elements, export_path, alpha, name):
    out_dict = {'model_name': name, 'num_elements': tot_num_elements, 'tensors': {}}
    for key in weights:
        out_dict['tensors'][key] = weights[key]

    with open(export_path + "weights_" + str(task.pid) + "_" + str(int(alpha*100)) + ".txt", 'w') as f:
        json.dump(out_dict, f)
    
    #check_weights(task, out_dict) # if ground truth weights available


def export_offsets(task, tensor_offsets, export_path, alpha):
    """
    Write heap addresses and offsets of Tensor structs to file for rehosting
    File format:
        First line contains integer n and m, the number of heaps in process and the number of tensors respectively.
        n lines follow containing addresses a and b, the start and end addresses of each heap respectively.
        m lines follow containing the name of the tensor and its address.
    """
    f = open(export_path + "offsets_" + str(task.pid) + "_" + str(int(alpha*100)) + ".txt", 'w')
    heaps = get_heaps(task)
    f.write(str(len(heaps)) + " " + str(len(tensor_offsets)) + "\n")
    for heap in heaps:
        f.write(str(hex(heap.vm_start)) + " " + str(hex(heap.vm_end)) + "\n")
    for name in tensor_offsets:
        f.write(name + " " + str(hex(tensor_offsets[name])) + "\n")
    f.close()


def process_parameters(task, addr_space, model, export_path, alpha):
    """
    Extract shape and other hyperparameters of each slot variable in Python layer
    """

    global recovered_c_structs
    global recovered_python_objects
    global false_positives
    global hyperparameters

    all_layers = []
    shape = OrderedDict()
    anonvar_to_name = {}
    tot_num_elements = 0
    distinct_layers = set()

    if model.ob_type.dereference().name == "FuncGraph":
        all_layers = extract_func_graph(addr_space, model)
    else:
        all_layers = bfs(model)

    model_dict = model.in_dict.dereference().val
    recovered_python_objects += 2

    for layer_dict in all_layers:
        print
        print layer_dict['_name']
        recovered_python_objects += 1

        ind = layer_dict['_name'].rfind("/")
        if ind == -1:
            ind = len(layer_dict['_name'])
        distinct_layers.add(layer_dict['_name'][0:ind])

        if "input" in layer_dict['_name']:
            shape[layer_dict['_name']] = list(layer_dict['_batch_input_shape'])
            recovered_python_objects += 1
            print "Input Shape:", list(layer_dict['_batch_input_shape'])

        elif "pool" in layer_dict['_name']:
            shape[layer_dict['_name']] = layer_dict['pool_size']
            recovered_python_objects += 1
            hyperparameters += 1
            print "Pool Size:", layer_dict['pool_size']

        elif "dropout" in layer_dict['_name']:
            shape[layer_dict['_name']] = layer_dict['rate']
            recovered_python_objects += 1
            hyperparameters += 1
            print "Rate:", layer_dict['rate']

        elif len(layer_dict['_trainable_weights']) == 0 and len(layer_dict['_non_trainable_weights']) == 0:
            shape[layer_dict['_name']] = None
            print "No Weights"
                
        for i in range(len(layer_dict['_trainable_weights'])):
            tensor_dict = layer_dict['_trainable_weights'][i].in_dict.dereference().val
            print "Name:", tensor_dict['_handle_name']
            print "Shape:", tensor_dict['_shape'].val
            recovered_python_objects += 2
            shape[tensor_dict['_handle_name']] = tensor_dict['_shape'].val
            anonvar_to_name[get_anonvar(tensor_dict, addr_space)] = tensor_dict['_handle_name']
            tot_num_elements += calc_tot(tensor_dict['_shape'].val)

        for i in range(len(layer_dict['_non_trainable_weights'])):
            tensor_dict = layer_dict['_non_trainable_weights'][i].in_dict.dereference().val
            print "Name:", tensor_dict['_handle_name']
            print "Shape:", tensor_dict['_shape'].val
            recovered_python_objects += 1
            shape[tensor_dict['_handle_name']] = tensor_dict['_shape'].val
            anonvar_to_name[get_anonvar(tensor_dict, addr_space)] = tensor_dict['_handle_name']
            tot_num_elements += calc_tot(tensor_dict['_shape'].val)

    print "Total elements:", tot_num_elements
    print anonvar_to_name
    print shape
    print (len(distinct_layers))
    print (distinct_layers)

    weights, addrs = scan_heap(task, addr_space, shape, anonvar_to_name)

    print "MODEL SUMMARY"
    for key in shape:
        print key
        print shape[key]
        print

    export_weights(task, weights, tot_num_elements, export_path, alpha, str(task.pid))
    export_offsets(task, addrs, export_path, alpha)

    print "EVAL TABLE SUMMARY"
    print "Layers:", len(all_layers)
    print "Distinct:", len(distinct_layers)
    print "Tensors:", len(anonvar_to_name)
    print "Weights:", tot_num_elements
    print "Hyper Parameters:", hyperparameters
    print "Precision:", len(anonvar_to_name), "/", len(anonvar_to_name) + false_positives, "=", float(len(anonvar_to_name)) / float(len(anonvar_to_name) + false_positives)
    print "Python Objects:", recovered_python_objects
    print "C Structs:", recovered_c_structs


def is_model(found_object, class_names):
    model_name = found_object.ob_type.dereference().name
    if model_name in class_names:
        return True
    elif model_name == "FuncGraph" and found_object.in_dict.dereference().val['name'] == "signature_wrapper":
        return True
    else:
        return False


def traverse_gc(task, addr_space, obj_type_string, start, stop, class_names, export_path, alpha):
    """
    Traverses the garbage collector generation (doubly linked list)
    Searches for model root
    """
    tmp = start
    
    global recovered_python_objects

    while True:
        found_head = obj.Object("_PyGC_Head", offset=tmp, vm=addr_space)
        found_object = obj.Object("_PyInstanceObject1",
                            offset=tmp + 32,
                            vm=addr_space)
        
        if not found_head.is_valid():
            print "_PyGC_Head invalid"
            sys.exit(0)
        
        recovered_python_objects += 2

        print "curr:", hex(tmp), "next:", hex(found_head.next_val), "prev:", hex(found_head.prev_val)
        print found_object.ob_type.dereference().name
        
        if is_model(found_object, class_names):
            print "Found", found_object.ob_type.dereference().name, "at", hex(found_object.obj_offset)
            process_parameters(task, addr_space, found_object, export_path, alpha)
            return True
        
        if (tmp == stop):
            break
        tmp = found_head.next_val
    return False


def get_profile_data():
    with open(PROFILE_PATH) as json_file:
        profile_data = json.load(json_file)
    return profile_data


def find_PyRuntime():
    profile_data = get_profile_data()
    for p in profile_data['globals']:
        if p['name'] == '_PyRuntime':
            return int(p['offset'],16)
    return -1


def find_model(task, class_names, export_path, alpha):
    """
    Go to _PyRuntimeState -> gc -> generations
    Traverse PyGC_Head pointers
    """
    start = timeit.default_timer()

    addr_space = task.get_process_address_space() 

    _PyRuntimeLoc = find_PyRuntime()

    print "_PyRuntime", hex(_PyRuntimeLoc)

    if _PyRuntimeLoc == -1:
        print "Failed to find any _pyruntime location"
        sys.exit(0)
    
    pyruntime = obj.Object("_PyRuntimeState",
                                  offset=_PyRuntimeLoc, #0xaa6560
                                  vm=addr_space)

    if not pyruntime.is_valid():
        print "Not _PyRuntimeState"
        sys.exit(0)
    
    if (traverse_gc(task=task, 
            addr_space=addr_space,
            obj_type_string="_PyGC_Head",
            start=pyruntime.gen1_next,
            stop=pyruntime.gen1_prev,
           class_names=class_names,
           export_path=export_path,
           alpha=alpha)):
           return
    if (traverse_gc(task=task, 
            addr_space=addr_space,
            obj_type_string="_PyGC_Head",
            start=pyruntime.gen2_next,
            stop=pyruntime.gen2_prev,
            class_names=class_names,
            export_path=export_path,
            alpha=alpha)):
            return
    if (traverse_gc(task=task, 
            addr_space=addr_space,
            obj_type_string="_PyGC_Head",
            start=pyruntime.gen3_next,
            stop=pyruntime.gen3_prev,
            class_names=class_names,
            export_path=export_path,
            alpha=alpha)):
            return
    
    print "Model Root not found"
    return


def read_addr_range(task, start, end):
	pagesize = 4096
	proc_as = task.get_process_address_space() # set as with our new kernel dtb to read from userland
	while start < end:
		page = proc_as.zread(start, pagesize)
		yield page
		start = start + pagesize


def dump_heaps(task, export_path, alpha):
    pid = int(task.pid)
    file_path = export_path + '%d_%d_dump' % (pid, alpha * 100)
    outfile = open(file_path, "wb+")
    for vma in task.get_proc_maps():
	    (fname, major, minor, ino, pgoff) = vma.info(task)
	    if str(fname) == '[heap]':
	    	for page in read_addr_range(task, vma.vm_start, vma.vm_end):
	    		outfile.write(page)


def _is_python_task(task, pidstr):
    """
    Checks if the task has the specified Python PID
    """
    if str(task.pid) != pidstr:
        return False
    else:
        return True


class mnist_weights(linux_pslist.linux_pslist):
    """
    Recovers Tensorflow model attributes from a Python process.
    Includes VType definitions.
    """
    def __init__(self, config, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
        self._config.add_option(
            'PID', short_option = 'p', default = None,
                          help = 'Operate on the Python Process ID',
                          action = 'store', type = 'str')

    def _validate_config(self):
        if self._config.PID is not None and len(self._config.PID.split(',')) != 1:
            debug.error("Please enter the process PID")
        
    def calculate(self):
        """
        Locate specified process and dump heap memory.
        """
        start = timeit.default_timer()
        linux_common.set_plugin_members(self)

        self._validate_config()
        pidstr = self._config.PID

        tasks = []
        for task in linux_pslist.linux_pslist.calculate(self):
            if _is_python_task(task, pidstr):
                tasks.append(task)

        alpha = 0.06
        export_path = './volatility_dumps/block_mobilenetv1/'

        for task in tasks:
            find_model(task, ["Sequential"], export_path, alpha)
            dump_heaps(task, export_path, alpha)

        stop = timeit.default_timer()
        print("\nRuntime: {0} seconds".format(stop - start))
        sys.exit(0)

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
            yield (0, [str(instance.string)])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Dict", "70")])
        for _, output in self.generator(data):
            self.table_row(outfd, *[str(o) for o in output])